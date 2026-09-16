rule TTP_XOR_WriteProcessMemory_59c8 {
  strings:
    $key_59c8 = { 0e ba [2] 3c 98 [2] 3a ad [2] 14 ad [2] 2b b1 }

  condition:
    any of them
}