rule TTP_XOR_WriteProcessMemory_5ec0 {
  strings:
    $key_5ec0 = { 09 b2 [2] 3b 90 [2] 3d a5 [2] 13 a5 [2] 2c b9 }

  condition:
    any of them
}