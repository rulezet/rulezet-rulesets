rule TTP_XOR_WriteProcessMemory_65c1 {
  strings:
    $key_65c1 = { 32 b3 [2] 00 91 [2] 06 a4 [2] 28 a4 [2] 17 b8 }

  condition:
    any of them
}