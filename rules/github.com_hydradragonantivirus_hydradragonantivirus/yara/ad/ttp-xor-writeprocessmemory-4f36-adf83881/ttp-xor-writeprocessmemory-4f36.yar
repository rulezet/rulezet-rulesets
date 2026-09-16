rule TTP_XOR_WriteProcessMemory_4f36 {
  strings:
    $key_4f36 = { 18 44 [2] 2a 66 [2] 2c 53 [2] 02 53 [2] 3d 4f }

  condition:
    any of them
}