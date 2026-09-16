rule TTP_XOR_WriteProcessMemory_5ec8 {
  strings:
    $key_5ec8 = { 09 ba [2] 3b 98 [2] 3d ad [2] 13 ad [2] 2c b1 }

  condition:
    any of them
}