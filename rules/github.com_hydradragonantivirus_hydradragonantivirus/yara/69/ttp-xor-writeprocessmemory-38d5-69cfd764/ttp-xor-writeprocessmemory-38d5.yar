rule TTP_XOR_WriteProcessMemory_38d5 {
  strings:
    $key_38d5 = { 6f a7 [2] 5d 85 [2] 5b b0 [2] 75 b0 [2] 4a ac }

  condition:
    any of them
}