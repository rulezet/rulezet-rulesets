rule TTP_XOR_WriteProcessMemory_48d5 {
  strings:
    $key_48d5 = { 1f a7 [2] 2d 85 [2] 2b b0 [2] 05 b0 [2] 3a ac }

  condition:
    any of them
}