rule TTP_XOR_WriteProcessMemory_2350 {
  strings:
    $key_2350 = { 74 22 [2] 46 00 [2] 40 35 [2] 6e 35 [2] 51 29 }

  condition:
    any of them
}