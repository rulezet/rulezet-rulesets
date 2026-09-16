rule TTP_XOR_WriteProcessMemory_3750 {
  strings:
    $key_3750 = { 60 22 [2] 52 00 [2] 54 35 [2] 7a 35 [2] 45 29 }

  condition:
    any of them
}