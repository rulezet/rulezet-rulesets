rule TTP_XOR_WriteProcessMemory_5ae6 {
  strings:
    $key_5ae6 = { 0d 94 [2] 3f b6 [2] 39 83 [2] 17 83 [2] 28 9f }

  condition:
    any of them
}