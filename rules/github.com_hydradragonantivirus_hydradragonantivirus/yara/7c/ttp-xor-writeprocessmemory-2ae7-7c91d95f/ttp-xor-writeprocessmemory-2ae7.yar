rule TTP_XOR_WriteProcessMemory_2ae7 {
  strings:
    $key_2ae7 = { 7d 95 [2] 4f b7 [2] 49 82 [2] 67 82 [2] 58 9e }

  condition:
    any of them
}