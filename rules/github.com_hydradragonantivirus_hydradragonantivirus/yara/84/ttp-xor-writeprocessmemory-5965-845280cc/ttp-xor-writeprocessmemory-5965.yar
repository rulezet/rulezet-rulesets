rule TTP_XOR_WriteProcessMemory_5965 {
  strings:
    $key_5965 = { 0e 17 [2] 3c 35 [2] 3a 00 [2] 14 00 [2] 2b 1c }

  condition:
    any of them
}