rule TTP_XOR_WriteProcessMemory_5f75 {
  strings:
    $key_5f75 = { 08 07 [2] 3a 25 [2] 3c 10 [2] 12 10 [2] 2d 0c }

  condition:
    any of them
}