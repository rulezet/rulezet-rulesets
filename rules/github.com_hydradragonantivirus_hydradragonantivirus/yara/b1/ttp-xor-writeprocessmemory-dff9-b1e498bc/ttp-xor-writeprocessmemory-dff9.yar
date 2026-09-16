rule TTP_XOR_WriteProcessMemory_dff9 {
  strings:
    $key_dff9 = { 88 8b [2] ba a9 [2] bc 9c [2] 92 9c [2] ad 80 }

  condition:
    any of them
}