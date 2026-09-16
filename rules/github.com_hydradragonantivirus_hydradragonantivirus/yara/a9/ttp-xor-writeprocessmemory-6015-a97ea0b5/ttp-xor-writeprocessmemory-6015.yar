rule TTP_XOR_WriteProcessMemory_6015 {
  strings:
    $key_6015 = { 37 67 [2] 05 45 [2] 03 70 [2] 2d 70 [2] 12 6c }

  condition:
    any of them
}