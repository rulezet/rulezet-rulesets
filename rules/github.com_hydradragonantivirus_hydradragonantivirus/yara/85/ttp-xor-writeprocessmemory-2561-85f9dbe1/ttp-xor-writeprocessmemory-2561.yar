rule TTP_XOR_WriteProcessMemory_2561 {
  strings:
    $key_2561 = { 72 13 [2] 40 31 [2] 46 04 [2] 68 04 [2] 57 18 }

  condition:
    any of them
}