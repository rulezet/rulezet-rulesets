rule TTP_XOR_WriteProcessMemory_4ae7 {
  strings:
    $key_4ae7 = { 1d 95 [2] 2f b7 [2] 29 82 [2] 07 82 [2] 38 9e }

  condition:
    any of them
}