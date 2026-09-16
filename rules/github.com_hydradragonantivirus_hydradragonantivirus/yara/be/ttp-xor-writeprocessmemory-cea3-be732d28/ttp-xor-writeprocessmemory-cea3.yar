rule TTP_XOR_WriteProcessMemory_cea3 {
  strings:
    $key_cea3 = { 99 d1 [2] ab f3 [2] ad c6 [2] 83 c6 [2] bc da }

  condition:
    any of them
}