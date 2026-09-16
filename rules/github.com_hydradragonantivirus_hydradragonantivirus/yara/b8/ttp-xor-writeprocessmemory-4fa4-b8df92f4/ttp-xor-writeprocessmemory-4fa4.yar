rule TTP_XOR_WriteProcessMemory_4fa4 {
  strings:
    $key_4fa4 = { 18 d6 [2] 2a f4 [2] 2c c1 [2] 02 c1 [2] 3d dd }

  condition:
    any of them
}