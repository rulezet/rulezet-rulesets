rule TTP_XOR_WriteProcessMemory_17c1 {
  strings:
    $key_17c1 = { 40 b3 [2] 72 91 [2] 74 a4 [2] 5a a4 [2] 65 b8 }

  condition:
    any of them
}