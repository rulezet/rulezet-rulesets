rule TTP_XOR_WriteProcessMemory_4e25 {
  strings:
    $key_4e25 = { 19 57 [2] 2b 75 [2] 2d 40 [2] 03 40 [2] 3c 5c }

  condition:
    any of them
}