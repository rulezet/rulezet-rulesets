rule TTP_XOR_WriteProcessMemory_75cc {
  strings:
    $key_75cc = { 22 be [2] 10 9c [2] 16 a9 [2] 38 a9 [2] 07 b5 }

  condition:
    any of them
}