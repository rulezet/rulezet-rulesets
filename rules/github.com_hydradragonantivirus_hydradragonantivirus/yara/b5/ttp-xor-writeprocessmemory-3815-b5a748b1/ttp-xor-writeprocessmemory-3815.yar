rule TTP_XOR_WriteProcessMemory_3815 {
  strings:
    $key_3815 = { 6f 67 [2] 5d 45 [2] 5b 70 [2] 75 70 [2] 4a 6c }

  condition:
    any of them
}