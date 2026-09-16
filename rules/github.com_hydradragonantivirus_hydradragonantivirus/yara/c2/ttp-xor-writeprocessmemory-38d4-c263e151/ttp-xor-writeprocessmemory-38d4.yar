rule TTP_XOR_WriteProcessMemory_38d4 {
  strings:
    $key_38d4 = { 6f a6 [2] 5d 84 [2] 5b b1 [2] 75 b1 [2] 4a ad }

  condition:
    any of them
}