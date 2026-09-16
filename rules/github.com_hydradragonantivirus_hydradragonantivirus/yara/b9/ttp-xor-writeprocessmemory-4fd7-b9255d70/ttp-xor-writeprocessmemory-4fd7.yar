rule TTP_XOR_WriteProcessMemory_4fd7 {
  strings:
    $key_4fd7 = { 18 a5 [2] 2a 87 [2] 2c b2 [2] 02 b2 [2] 3d ae }

  condition:
    any of them
}