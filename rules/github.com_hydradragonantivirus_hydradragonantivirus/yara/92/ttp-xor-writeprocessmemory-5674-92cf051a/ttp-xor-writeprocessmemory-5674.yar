rule TTP_XOR_WriteProcessMemory_5674 {
  strings:
    $key_5674 = { 01 06 [2] 33 24 [2] 35 11 [2] 1b 11 [2] 24 0d }

  condition:
    any of them
}