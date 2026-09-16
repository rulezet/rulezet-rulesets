rule TTP_XOR_WriteProcessMemory_6835 {
  strings:
    $key_6835 = { 3f 47 [2] 0d 65 [2] 0b 50 [2] 25 50 [2] 1a 4c }

  condition:
    any of them
}