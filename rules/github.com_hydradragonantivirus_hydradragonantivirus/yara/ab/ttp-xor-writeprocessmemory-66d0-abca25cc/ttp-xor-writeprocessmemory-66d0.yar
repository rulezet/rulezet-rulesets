rule TTP_XOR_WriteProcessMemory_66d0 {
  strings:
    $key_66d0 = { 31 a2 [2] 03 80 [2] 05 b5 [2] 2b b5 [2] 14 a9 }

  condition:
    any of them
}