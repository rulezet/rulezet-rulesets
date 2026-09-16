rule TTP_XOR_WriteProcessMemory_5af7 {
  strings:
    $key_5af7 = { 0d 85 [2] 3f a7 [2] 39 92 [2] 17 92 [2] 28 8e }

  condition:
    any of them
}