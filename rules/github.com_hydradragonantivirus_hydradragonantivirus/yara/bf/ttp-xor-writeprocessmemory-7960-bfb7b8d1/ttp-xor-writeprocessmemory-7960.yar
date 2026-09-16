rule TTP_XOR_WriteProcessMemory_7960 {
  strings:
    $key_7960 = { 2e 12 [2] 1c 30 [2] 1a 05 [2] 34 05 [2] 0b 19 }

  condition:
    any of them
}