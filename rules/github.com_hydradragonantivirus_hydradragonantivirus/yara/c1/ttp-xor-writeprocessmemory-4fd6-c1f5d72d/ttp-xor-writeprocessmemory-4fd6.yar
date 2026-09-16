rule TTP_XOR_WriteProcessMemory_4fd6 {
  strings:
    $key_4fd6 = { 18 a4 [2] 2a 86 [2] 2c b3 [2] 02 b3 [2] 3d af }

  condition:
    any of them
}