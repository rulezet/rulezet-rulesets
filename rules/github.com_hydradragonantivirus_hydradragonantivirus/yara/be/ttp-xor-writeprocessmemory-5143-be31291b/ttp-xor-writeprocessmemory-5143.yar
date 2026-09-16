rule TTP_XOR_WriteProcessMemory_5143 {
  strings:
    $key_5143 = { 06 31 [2] 34 13 [2] 32 26 [2] 1c 26 [2] 23 3a }

  condition:
    any of them
}