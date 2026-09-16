rule TTP_XOR_WriteProcessMemory_6005 {
  strings:
    $key_6005 = { 37 77 [2] 05 55 [2] 03 60 [2] 2d 60 [2] 12 7c }

  condition:
    any of them
}