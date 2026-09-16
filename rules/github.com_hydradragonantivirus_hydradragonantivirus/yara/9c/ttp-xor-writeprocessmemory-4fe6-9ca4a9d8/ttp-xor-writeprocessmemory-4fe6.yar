rule TTP_XOR_WriteProcessMemory_4fe6 {
  strings:
    $key_4fe6 = { 18 94 [2] 2a b6 [2] 2c 83 [2] 02 83 [2] 3d 9f }

  condition:
    any of them
}