rule TTP_XOR_WriteProcessMemory_4777 {
  strings:
    $key_4777 = { 10 05 [2] 22 27 [2] 24 12 [2] 0a 12 [2] 35 0e }

  condition:
    any of them
}