rule TTP_XOR_WriteProcessMemory_ced0 {
  strings:
    $key_ced0 = { 99 a2 [2] ab 80 [2] ad b5 [2] 83 b5 [2] bc a9 }

  condition:
    any of them
}