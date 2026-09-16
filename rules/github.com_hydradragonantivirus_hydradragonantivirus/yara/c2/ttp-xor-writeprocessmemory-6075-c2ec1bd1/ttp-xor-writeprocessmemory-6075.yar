rule TTP_XOR_WriteProcessMemory_6075 {
  strings:
    $key_6075 = { 37 07 [2] 05 25 [2] 03 10 [2] 2d 10 [2] 12 0c }

  condition:
    any of them
}