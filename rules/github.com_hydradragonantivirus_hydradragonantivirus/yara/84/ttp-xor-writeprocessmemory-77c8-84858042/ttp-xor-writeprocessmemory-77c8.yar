rule TTP_XOR_WriteProcessMemory_77c8 {
  strings:
    $key_77c8 = { 20 ba [2] 12 98 [2] 14 ad [2] 3a ad [2] 05 b1 }

  condition:
    any of them
}