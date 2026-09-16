rule TTP_XOR_WriteProcessMemory_dfc1 {
  strings:
    $key_dfc1 = { 88 b3 [2] ba 91 [2] bc a4 [2] 92 a4 [2] ad b8 }

  condition:
    any of them
}