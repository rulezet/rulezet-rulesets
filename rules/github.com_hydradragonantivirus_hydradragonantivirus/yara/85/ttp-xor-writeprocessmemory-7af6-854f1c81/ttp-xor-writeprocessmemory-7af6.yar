rule TTP_XOR_WriteProcessMemory_7af6 {
  strings:
    $key_7af6 = { 2d 84 [2] 1f a6 [2] 19 93 [2] 37 93 [2] 08 8f }

  condition:
    any of them
}