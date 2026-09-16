rule TTP_XOR_WriteProcessMemory_5c43 {
  strings:
    $key_5c43 = { 0b 31 [2] 39 13 [2] 3f 26 [2] 11 26 [2] 2e 3a }

  condition:
    any of them
}