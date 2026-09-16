rule TTP_XOR_WriteProcessMemory_23cc {
  strings:
    $key_23cc = { 74 be [2] 46 9c [2] 40 a9 [2] 6e a9 [2] 51 b5 }

  condition:
    any of them
}