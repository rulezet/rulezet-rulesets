rule TTP_XOR_WriteProcessMemory_5055 {
  strings:
    $key_5055 = { 07 27 [2] 35 05 [2] 33 30 [2] 1d 30 [2] 22 2c }

  condition:
    any of them
}