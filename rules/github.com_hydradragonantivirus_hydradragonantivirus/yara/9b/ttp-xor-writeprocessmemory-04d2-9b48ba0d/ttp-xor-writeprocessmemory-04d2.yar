rule TTP_XOR_WriteProcessMemory_04d2 {
  strings:
    $key_04d2 = { 53 a0 [2] 61 82 [2] 67 b7 [2] 49 b7 [2] 76 ab }

  condition:
    any of them
}