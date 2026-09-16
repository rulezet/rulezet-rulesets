rule TTP_XOR_WriteProcessMemory_1b43 {
  strings:
    $key_1b43 = { 4c 31 [2] 7e 13 [2] 78 26 [2] 56 26 [2] 69 3a }

  condition:
    any of them
}