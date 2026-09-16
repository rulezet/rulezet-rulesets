rule TTP_XOR_WriteProcessMemory_5022 {
  strings:
    $key_5022 = { 07 50 [2] 35 72 [2] 33 47 [2] 1d 47 [2] 22 5b }

  condition:
    any of them
}