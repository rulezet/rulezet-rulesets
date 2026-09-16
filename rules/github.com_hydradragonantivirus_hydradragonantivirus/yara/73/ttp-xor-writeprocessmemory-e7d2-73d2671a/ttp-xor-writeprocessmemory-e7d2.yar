rule TTP_XOR_WriteProcessMemory_e7d2 {
  strings:
    $key_e7d2 = { b0 a0 [2] 82 82 [2] 84 b7 [2] aa b7 [2] 95 ab }

  condition:
    any of them
}