rule TTP_XOR_WriteProcessMemory_66d1 {
  strings:
    $key_66d1 = { 31 a3 [2] 03 81 [2] 05 b4 [2] 2b b4 [2] 14 a8 }

  condition:
    any of them
}