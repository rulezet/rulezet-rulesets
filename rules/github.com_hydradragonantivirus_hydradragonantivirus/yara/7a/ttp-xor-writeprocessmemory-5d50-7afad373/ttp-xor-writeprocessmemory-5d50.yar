rule TTP_XOR_WriteProcessMemory_5d50 {
  strings:
    $key_5d50 = { 0a 22 [2] 38 00 [2] 3e 35 [2] 10 35 [2] 2f 29 }

  condition:
    any of them
}