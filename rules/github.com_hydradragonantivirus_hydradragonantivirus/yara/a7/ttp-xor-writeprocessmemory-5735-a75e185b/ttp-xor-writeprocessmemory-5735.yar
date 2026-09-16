rule TTP_XOR_WriteProcessMemory_5735 {
  strings:
    $key_5735 = { 00 47 [2] 32 65 [2] 34 50 [2] 1a 50 [2] 25 4c }

  condition:
    any of them
}