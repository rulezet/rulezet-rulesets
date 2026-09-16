rule TTP_XOR_WriteProcessMemory_e2c3 {
  strings:
    $key_e2c3 = { b5 b1 [2] 87 93 [2] 81 a6 [2] af a6 [2] 90 ba }

  condition:
    any of them
}