rule TTP_XOR_WriteProcessMemory_dff4 {
  strings:
    $key_dff4 = { 88 86 [2] ba a4 [2] bc 91 [2] 92 91 [2] ad 8d }

  condition:
    any of them
}