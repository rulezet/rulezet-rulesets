rule TTP_XOR_WriteProcessMemory_4ff3 {
  strings:
    $key_4ff3 = { 18 81 [2] 2a a3 [2] 2c 96 [2] 02 96 [2] 3d 8a }

  condition:
    any of them
}