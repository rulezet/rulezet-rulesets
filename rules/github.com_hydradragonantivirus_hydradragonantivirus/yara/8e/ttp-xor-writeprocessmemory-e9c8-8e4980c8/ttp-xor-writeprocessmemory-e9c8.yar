rule TTP_XOR_WriteProcessMemory_e9c8 {
  strings:
    $key_e9c8 = { be ba [2] 8c 98 [2] 8a ad [2] a4 ad [2] 9b b1 }

  condition:
    any of them
}