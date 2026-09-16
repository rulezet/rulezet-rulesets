rule TTP_XOR_WriteProcessMemory_08d8 {
  strings:
    $key_08d8 = { 5f aa [2] 6d 88 [2] 6b bd [2] 45 bd [2] 7a a1 }

  condition:
    any of them
}