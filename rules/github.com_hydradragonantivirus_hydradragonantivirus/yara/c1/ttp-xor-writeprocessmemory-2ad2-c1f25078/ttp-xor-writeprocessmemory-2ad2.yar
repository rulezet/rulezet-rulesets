rule TTP_XOR_WriteProcessMemory_2ad2 {
  strings:
    $key_2ad2 = { 7d a0 [2] 4f 82 [2] 49 b7 [2] 67 b7 [2] 58 ab }

  condition:
    any of them
}