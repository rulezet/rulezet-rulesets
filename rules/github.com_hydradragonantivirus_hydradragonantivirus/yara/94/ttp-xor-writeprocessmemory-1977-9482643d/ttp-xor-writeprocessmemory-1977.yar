rule TTP_XOR_WriteProcessMemory_1977 {
  strings:
    $key_1977 = { 4e 05 [2] 7c 27 [2] 7a 12 [2] 54 12 [2] 6b 0e }

  condition:
    any of them
}