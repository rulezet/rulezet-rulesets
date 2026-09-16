rule TTP_XOR_WriteProcessMemory_e2c7 {
  strings:
    $key_e2c7 = { b5 b5 [2] 87 97 [2] 81 a2 [2] af a2 [2] 90 be }

  condition:
    any of them
}