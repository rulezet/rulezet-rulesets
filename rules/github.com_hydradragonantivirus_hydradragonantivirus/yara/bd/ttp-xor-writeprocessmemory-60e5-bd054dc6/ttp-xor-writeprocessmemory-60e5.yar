rule TTP_XOR_WriteProcessMemory_60e5 {
  strings:
    $key_60e5 = { 37 97 [2] 05 b5 [2] 03 80 [2] 2d 80 [2] 12 9c }

  condition:
    any of them
}