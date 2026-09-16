rule TTP_XOR_WriteProcessMemory_6825 {
  strings:
    $key_6825 = { 3f 57 [2] 0d 75 [2] 0b 40 [2] 25 40 [2] 1a 5c }

  condition:
    any of them
}