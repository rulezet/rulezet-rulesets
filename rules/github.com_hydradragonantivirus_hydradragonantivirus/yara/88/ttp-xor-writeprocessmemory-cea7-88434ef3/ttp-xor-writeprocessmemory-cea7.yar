rule TTP_XOR_WriteProcessMemory_cea7 {
  strings:
    $key_cea7 = { 99 d5 [2] ab f7 [2] ad c2 [2] 83 c2 [2] bc de }

  condition:
    any of them
}