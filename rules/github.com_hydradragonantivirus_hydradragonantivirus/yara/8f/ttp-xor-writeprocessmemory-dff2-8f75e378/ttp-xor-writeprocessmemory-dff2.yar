rule TTP_XOR_WriteProcessMemory_dff2 {
  strings:
    $key_dff2 = { 88 80 [2] ba a2 [2] bc 97 [2] 92 97 [2] ad 8b }

  condition:
    any of them
}