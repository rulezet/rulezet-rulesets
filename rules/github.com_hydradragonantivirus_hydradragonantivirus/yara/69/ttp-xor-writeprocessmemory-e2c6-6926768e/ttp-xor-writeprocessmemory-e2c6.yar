rule TTP_XOR_WriteProcessMemory_e2c6 {
  strings:
    $key_e2c6 = { b5 b4 [2] 87 96 [2] 81 a3 [2] af a3 [2] 90 bf }

  condition:
    any of them
}