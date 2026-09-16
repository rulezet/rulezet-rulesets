rule TTP_XOR_WriteProcessMemory_1835 {
  strings:
    $key_1835 = { 4f 47 [2] 7d 65 [2] 7b 50 [2] 55 50 [2] 6a 4c }

  condition:
    any of them
}