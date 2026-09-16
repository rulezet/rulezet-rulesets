rule TTP_XOR_WriteProcessMemory_6055 {
  strings:
    $key_6055 = { 37 27 [2] 05 05 [2] 03 30 [2] 2d 30 [2] 12 2c }

  condition:
    any of them
}