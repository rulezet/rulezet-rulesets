rule TTP_XOR_WriteProcessMemory_dfc7 {
  strings:
    $key_dfc7 = { 88 b5 [2] ba 97 [2] bc a2 [2] 92 a2 [2] ad be }

  condition:
    any of them
}