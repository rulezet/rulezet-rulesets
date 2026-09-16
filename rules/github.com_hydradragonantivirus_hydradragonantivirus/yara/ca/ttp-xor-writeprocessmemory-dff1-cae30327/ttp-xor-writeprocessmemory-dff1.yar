rule TTP_XOR_WriteProcessMemory_dff1 {
  strings:
    $key_dff1 = { 88 83 [2] ba a1 [2] bc 94 [2] 92 94 [2] ad 88 }

  condition:
    any of them
}