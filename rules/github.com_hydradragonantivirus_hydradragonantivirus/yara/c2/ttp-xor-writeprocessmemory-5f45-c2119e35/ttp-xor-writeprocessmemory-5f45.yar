rule TTP_XOR_WriteProcessMemory_5f45 {
  strings:
    $key_5f45 = { 08 37 [2] 3a 15 [2] 3c 20 [2] 12 20 [2] 2d 3c }

  condition:
    any of them
}