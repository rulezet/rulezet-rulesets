rule TTP_XOR_WriteProcessMemory_45cc {
  strings:
    $key_45cc = { 12 be [2] 20 9c [2] 26 a9 [2] 08 a9 [2] 37 b5 }

  condition:
    any of them
}