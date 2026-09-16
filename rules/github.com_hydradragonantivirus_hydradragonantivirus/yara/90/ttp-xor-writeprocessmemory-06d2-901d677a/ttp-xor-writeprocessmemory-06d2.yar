rule TTP_XOR_WriteProcessMemory_06d2 {
  strings:
    $key_06d2 = { 51 a0 [2] 63 82 [2] 65 b7 [2] 4b b7 [2] 74 ab }

  condition:
    any of them
}