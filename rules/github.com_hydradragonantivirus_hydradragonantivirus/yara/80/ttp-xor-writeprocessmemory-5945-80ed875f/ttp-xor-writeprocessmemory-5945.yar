rule TTP_XOR_WriteProcessMemory_5945 {
  strings:
    $key_5945 = { 0e 37 [2] 3c 15 [2] 3a 20 [2] 14 20 [2] 2b 3c }

  condition:
    any of them
}