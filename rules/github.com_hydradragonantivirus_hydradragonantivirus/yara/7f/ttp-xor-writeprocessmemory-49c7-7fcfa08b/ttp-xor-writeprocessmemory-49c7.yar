rule TTP_XOR_WriteProcessMemory_49c7 {
  strings:
    $key_49c7 = { 1e b5 [2] 2c 97 [2] 2a a2 [2] 04 a2 [2] 3b be }

  condition:
    any of them
}