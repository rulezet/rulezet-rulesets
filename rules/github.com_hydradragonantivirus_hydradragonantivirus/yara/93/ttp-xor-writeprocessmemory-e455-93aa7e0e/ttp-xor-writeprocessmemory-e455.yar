rule TTP_XOR_WriteProcessMemory_e455 {
  strings:
    $key_e455 = { b3 27 [2] 81 05 [2] 87 30 [2] a9 30 [2] 96 2c }

  condition:
    any of them
}