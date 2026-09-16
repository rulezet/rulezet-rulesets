rule TTP_XOR_WriteProcessMemory_90cc {
  strings:
    $key_90cc = { c7 be [2] f5 9c [2] f3 a9 [2] dd a9 [2] e2 b5 }

  condition:
    any of them
}