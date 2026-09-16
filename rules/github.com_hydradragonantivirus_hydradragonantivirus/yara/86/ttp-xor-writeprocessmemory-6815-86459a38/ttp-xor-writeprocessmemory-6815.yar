rule TTP_XOR_WriteProcessMemory_6815 {
  strings:
    $key_6815 = { 3f 67 [2] 0d 45 [2] 0b 70 [2] 25 70 [2] 1a 6c }

  condition:
    any of them
}