rule TTP_XOR_WriteProcessMemory_572d {
  strings:
    $key_572d = { 00 5f [2] 32 7d [2] 34 48 [2] 1a 48 [2] 25 54 }

  condition:
    any of them
}