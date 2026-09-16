rule TTP_XOR_WriteProcessMemory_64d2 {
  strings:
    $key_64d2 = { 33 a0 [2] 01 82 [2] 07 b7 [2] 29 b7 [2] 16 ab }

  condition:
    any of them
}