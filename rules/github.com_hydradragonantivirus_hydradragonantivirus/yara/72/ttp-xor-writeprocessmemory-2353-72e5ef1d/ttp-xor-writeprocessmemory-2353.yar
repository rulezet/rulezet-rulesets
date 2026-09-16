rule TTP_XOR_WriteProcessMemory_2353 {
  strings:
    $key_2353 = { 74 21 [2] 46 03 [2] 40 36 [2] 6e 36 [2] 51 2a }

  condition:
    any of them
}