rule TTP_XOR_WriteProcessMemory_7af7 {
  strings:
    $key_7af7 = { 2d 85 [2] 1f a7 [2] 19 92 [2] 37 92 [2] 08 8e }

  condition:
    any of them
}