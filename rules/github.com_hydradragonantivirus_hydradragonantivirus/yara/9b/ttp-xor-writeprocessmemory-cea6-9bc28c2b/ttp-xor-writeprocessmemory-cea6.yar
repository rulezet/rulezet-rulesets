rule TTP_XOR_WriteProcessMemory_cea6 {
  strings:
    $key_cea6 = { 99 d4 [2] ab f6 [2] ad c3 [2] 83 c3 [2] bc df }

  condition:
    any of them
}