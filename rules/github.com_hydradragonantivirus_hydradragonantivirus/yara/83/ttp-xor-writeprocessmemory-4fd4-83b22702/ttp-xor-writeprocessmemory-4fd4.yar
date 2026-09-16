rule TTP_XOR_WriteProcessMemory_4fd4 {
  strings:
    $key_4fd4 = { 18 a6 [2] 2a 84 [2] 2c b1 [2] 02 b1 [2] 3d ad }

  condition:
    any of them
}