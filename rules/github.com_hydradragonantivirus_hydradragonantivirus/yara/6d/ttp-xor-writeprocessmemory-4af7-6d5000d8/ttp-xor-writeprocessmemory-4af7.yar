rule TTP_XOR_WriteProcessMemory_4af7 {
  strings:
    $key_4af7 = { 1d 85 [2] 2f a7 [2] 29 92 [2] 07 92 [2] 38 8e }

  condition:
    any of them
}