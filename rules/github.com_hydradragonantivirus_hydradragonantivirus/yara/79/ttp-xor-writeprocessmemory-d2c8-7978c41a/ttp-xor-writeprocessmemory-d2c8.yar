rule TTP_XOR_WriteProcessMemory_d2c8 {
  strings:
    $key_d2c8 = { 85 ba [2] b7 98 [2] b1 ad [2] 9f ad [2] a0 b1 }

  condition:
    any of them
}