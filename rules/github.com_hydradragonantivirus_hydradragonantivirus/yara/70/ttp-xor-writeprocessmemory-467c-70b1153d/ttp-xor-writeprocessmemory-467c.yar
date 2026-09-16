rule TTP_XOR_WriteProcessMemory_467c {
  strings:
    $key_467c = { 11 0e [2] 23 2c [2] 25 19 [2] 0b 19 [2] 34 05 }

  condition:
    any of them
}