rule TTP_XOR_WriteProcessMemory_dfd3 {
  strings:
    $key_dfd3 = { 88 a1 [2] ba 83 [2] bc b6 [2] 92 b6 [2] ad aa }

  condition:
    any of them
}