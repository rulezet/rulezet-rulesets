rule TTP_XOR_WriteProcessMemory_cea0 {
  strings:
    $key_cea0 = { 99 d2 [2] ab f0 [2] ad c5 [2] 83 c5 [2] bc d9 }

  condition:
    any of them
}