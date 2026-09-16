rule TTP_XOR_WriteProcessMemory_5907 {
  strings:
    $key_5907 = { 0e 75 [2] 3c 57 [2] 3a 62 [2] 14 62 [2] 2b 7e }

  condition:
    any of them
}