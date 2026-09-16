rule TTP_XOR_WriteProcessMemory_2530 {
  strings:
    $key_2530 = { 72 42 [2] 40 60 [2] 46 55 [2] 68 55 [2] 57 49 }

  condition:
    any of them
}