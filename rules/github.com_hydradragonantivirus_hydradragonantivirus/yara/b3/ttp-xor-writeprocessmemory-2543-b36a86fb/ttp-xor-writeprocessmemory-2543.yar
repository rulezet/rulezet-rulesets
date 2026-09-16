rule TTP_XOR_WriteProcessMemory_2543 {
  strings:
    $key_2543 = { 72 31 [2] 40 13 [2] 46 26 [2] 68 26 [2] 57 3a }

  condition:
    any of them
}