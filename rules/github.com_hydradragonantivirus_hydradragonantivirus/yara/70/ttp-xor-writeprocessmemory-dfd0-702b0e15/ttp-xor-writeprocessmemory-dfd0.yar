rule TTP_XOR_WriteProcessMemory_dfd0 {
  strings:
    $key_dfd0 = { 88 a2 [2] ba 80 [2] bc b5 [2] 92 b5 [2] ad a9 }

  condition:
    any of them
}