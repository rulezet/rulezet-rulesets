rule TTP_XOR_WriteProcessMemory_4fd3 {
  strings:
    $key_4fd3 = { 18 a1 [2] 2a 83 [2] 2c b6 [2] 02 b6 [2] 3d aa }

  condition:
    any of them
}