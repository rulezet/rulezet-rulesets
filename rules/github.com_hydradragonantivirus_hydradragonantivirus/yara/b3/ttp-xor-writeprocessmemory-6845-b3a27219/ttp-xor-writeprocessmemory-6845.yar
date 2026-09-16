rule TTP_XOR_WriteProcessMemory_6845 {
  strings:
    $key_6845 = { 3f 37 [2] 0d 15 [2] 0b 20 [2] 25 20 [2] 1a 3c }

  condition:
    any of them
}