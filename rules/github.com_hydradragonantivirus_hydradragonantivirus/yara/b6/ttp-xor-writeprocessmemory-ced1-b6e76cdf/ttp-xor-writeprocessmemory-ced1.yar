rule TTP_XOR_WriteProcessMemory_ced1 {
  strings:
    $key_ced1 = { 99 a3 [2] ab 81 [2] ad b4 [2] 83 b4 [2] bc a8 }

  condition:
    any of them
}