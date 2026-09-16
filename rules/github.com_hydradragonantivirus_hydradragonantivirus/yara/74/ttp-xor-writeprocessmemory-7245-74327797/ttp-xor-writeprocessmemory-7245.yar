rule TTP_XOR_WriteProcessMemory_7245 {
  strings:
    $key_7245 = { 25 37 [2] 17 15 [2] 11 20 [2] 3f 20 [2] 00 3c }

  condition:
    any of them
}