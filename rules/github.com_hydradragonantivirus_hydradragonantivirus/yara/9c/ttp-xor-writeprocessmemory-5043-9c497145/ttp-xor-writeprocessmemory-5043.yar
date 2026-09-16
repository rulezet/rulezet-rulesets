rule TTP_XOR_WriteProcessMemory_5043 {
  strings:
    $key_5043 = { 07 31 [2] 35 13 [2] 33 26 [2] 1d 26 [2] 22 3a }

  condition:
    any of them
}