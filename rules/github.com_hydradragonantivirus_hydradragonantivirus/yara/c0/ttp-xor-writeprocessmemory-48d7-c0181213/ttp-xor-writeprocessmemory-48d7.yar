rule TTP_XOR_WriteProcessMemory_48d7 {
  strings:
    $key_48d7 = { 1f a5 [2] 2d 87 [2] 2b b2 [2] 05 b2 [2] 3a ae }

  condition:
    any of them
}