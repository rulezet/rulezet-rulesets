rule TTP_XOR_WriteProcessMemory_6b50 {
  strings:
    $key_6b50 = { 3c 22 [2] 0e 00 [2] 08 35 [2] 26 35 [2] 19 29 }

  condition:
    any of them
}