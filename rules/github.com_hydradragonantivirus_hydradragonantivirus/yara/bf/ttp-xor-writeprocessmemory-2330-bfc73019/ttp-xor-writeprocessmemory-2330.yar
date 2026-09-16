rule TTP_XOR_WriteProcessMemory_2330 {
  strings:
    $key_2330 = { 74 42 [2] 46 60 [2] 40 55 [2] 6e 55 [2] 51 49 }

  condition:
    any of them
}