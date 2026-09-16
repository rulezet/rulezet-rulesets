rule TTP_XOR_WriteProcessMemory_18d8 {
  strings:
    $key_18d8 = { 4f aa [2] 7d 88 [2] 7b bd [2] 55 bd [2] 6a a1 }

  condition:
    any of them
}