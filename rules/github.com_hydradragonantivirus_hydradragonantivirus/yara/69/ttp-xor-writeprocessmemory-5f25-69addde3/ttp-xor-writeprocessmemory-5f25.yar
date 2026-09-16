rule TTP_XOR_WriteProcessMemory_5f25 {
  strings:
    $key_5f25 = { 08 57 [2] 3a 75 [2] 3c 40 [2] 12 40 [2] 2d 5c }

  condition:
    any of them
}