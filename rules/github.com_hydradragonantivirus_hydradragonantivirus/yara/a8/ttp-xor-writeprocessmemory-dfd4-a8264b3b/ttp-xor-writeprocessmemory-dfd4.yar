rule TTP_XOR_WriteProcessMemory_dfd4 {
  strings:
    $key_dfd4 = { 88 a6 [2] ba 84 [2] bc b1 [2] 92 b1 [2] ad ad }

  condition:
    any of them
}