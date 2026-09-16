rule TTP_XOR_WriteProcessMemory_5970 {
  strings:
    $key_5970 = { 0e 02 [2] 3c 20 [2] 3a 15 [2] 14 15 [2] 2b 09 }

  condition:
    any of them
}