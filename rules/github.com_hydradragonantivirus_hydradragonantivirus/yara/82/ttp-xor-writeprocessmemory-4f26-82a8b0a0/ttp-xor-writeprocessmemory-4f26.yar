rule TTP_XOR_WriteProcessMemory_4f26 {
  strings:
    $key_4f26 = { 18 54 [2] 2a 76 [2] 2c 43 [2] 02 43 [2] 3d 5f }

  condition:
    any of them
}