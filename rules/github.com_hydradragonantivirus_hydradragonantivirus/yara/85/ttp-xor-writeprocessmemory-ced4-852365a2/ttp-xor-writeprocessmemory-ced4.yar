rule TTP_XOR_WriteProcessMemory_ced4 {
  strings:
    $key_ced4 = { 99 a6 [2] ab 84 [2] ad b1 [2] 83 b1 [2] bc ad }

  condition:
    any of them
}