rule TTP_XOR_WriteProcessMemory_5673 {
  strings:
    $key_5673 = { 01 01 [2] 33 23 [2] 35 16 [2] 1b 16 [2] 24 0a }

  condition:
    any of them
}