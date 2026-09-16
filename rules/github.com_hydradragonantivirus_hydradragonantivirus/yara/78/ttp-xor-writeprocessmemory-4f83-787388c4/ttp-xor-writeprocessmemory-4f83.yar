rule TTP_XOR_WriteProcessMemory_4f83 {
  strings:
    $key_4f83 = { 18 f1 [2] 2a d3 [2] 2c e6 [2] 02 e6 [2] 3d fa }

  condition:
    any of them
}