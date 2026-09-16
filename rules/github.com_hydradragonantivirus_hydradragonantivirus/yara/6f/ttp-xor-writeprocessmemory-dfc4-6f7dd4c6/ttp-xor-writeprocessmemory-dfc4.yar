rule TTP_XOR_WriteProcessMemory_dfc4 {
  strings:
    $key_dfc4 = { 88 b6 [2] ba 94 [2] bc a1 [2] 92 a1 [2] ad bd }

  condition:
    any of them
}