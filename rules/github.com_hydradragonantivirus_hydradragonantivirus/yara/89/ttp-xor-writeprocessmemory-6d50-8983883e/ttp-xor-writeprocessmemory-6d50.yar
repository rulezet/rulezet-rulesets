rule TTP_XOR_WriteProcessMemory_6d50 {
  strings:
    $key_6d50 = { 3a 22 [2] 08 00 [2] 0e 35 [2] 20 35 [2] 1f 29 }

  condition:
    any of them
}