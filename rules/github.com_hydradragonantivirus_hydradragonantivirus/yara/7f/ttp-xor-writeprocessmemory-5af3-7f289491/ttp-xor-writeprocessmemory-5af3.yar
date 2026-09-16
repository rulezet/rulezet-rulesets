rule TTP_XOR_WriteProcessMemory_5af3 {
  strings:
    $key_5af3 = { 0d 81 [2] 3f a3 [2] 39 96 [2] 17 96 [2] 28 8a }

  condition:
    any of them
}