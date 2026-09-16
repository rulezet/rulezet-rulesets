rule TTP_XOR_WriteProcessMemory_4fd1 {
  strings:
    $key_4fd1 = { 18 a3 [2] 2a 81 [2] 2c b4 [2] 02 b4 [2] 3d a8 }

  condition:
    any of them
}