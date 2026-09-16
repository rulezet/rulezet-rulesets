rule TTP_XOR_WriteProcessMemory_4320 {
  strings:
    $key_4320 = { 14 52 [2] 26 70 [2] 20 45 [2] 0e 45 [2] 31 59 }

  condition:
    any of them
}