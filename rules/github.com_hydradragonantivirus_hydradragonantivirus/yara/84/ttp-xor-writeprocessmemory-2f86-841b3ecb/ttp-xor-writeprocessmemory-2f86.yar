rule TTP_XOR_WriteProcessMemory_2f86 {
  strings:
    $key_2f86 = { 78 f4 [2] 4a d6 [2] 4c e3 [2] 62 e3 [2] 5d ff }

  condition:
    any of them
}