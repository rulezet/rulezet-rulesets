rule TTP_XOR_WriteProcessMemory_cea1 {
  strings:
    $key_cea1 = { 99 d3 [2] ab f1 [2] ad c4 [2] 83 c4 [2] bc d8 }

  condition:
    any of them
}