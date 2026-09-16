rule TTP_XOR_WriteProcessMemory_7ae6 {
  strings:
    $key_7ae6 = { 2d 94 [2] 1f b6 [2] 19 83 [2] 37 83 [2] 08 9f }

  condition:
    any of them
}