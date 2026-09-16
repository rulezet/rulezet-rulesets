rule TTP_XOR_WriteProcessMemory_1045 {
  strings:
    $key_1045 = { 47 37 [2] 75 15 [2] 73 20 [2] 5d 20 [2] 62 3c }

  condition:
    any of them
}