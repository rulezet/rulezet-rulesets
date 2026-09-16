rule TTP_XOR_WriteProcessMemory_7845 {
  strings:
    $key_7845 = { 2f 37 [2] 1d 15 [2] 1b 20 [2] 35 20 [2] 0a 3c }

  condition:
    any of them
}