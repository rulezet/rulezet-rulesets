rule TTP_XOR_WriteProcessMemory_3b43 {
  strings:
    $key_3b43 = { 6c 31 [2] 5e 13 [2] 58 26 [2] 76 26 [2] 49 3a }

  condition:
    any of them
}