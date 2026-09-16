rule TTP_XOR_WriteProcessMemory_6f86 {
  strings:
    $key_6f86 = { 38 f4 [2] 0a d6 [2] 0c e3 [2] 22 e3 [2] 1d ff }

  condition:
    any of them
}