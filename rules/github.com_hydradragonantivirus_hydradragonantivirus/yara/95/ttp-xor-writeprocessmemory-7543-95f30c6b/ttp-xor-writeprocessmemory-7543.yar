rule TTP_XOR_WriteProcessMemory_7543 {
  strings:
    $key_7543 = { 22 31 [2] 10 13 [2] 16 26 [2] 38 26 [2] 07 3a }

  condition:
    any of them
}