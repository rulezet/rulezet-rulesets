rule TTP_XOR_WriteProcessMemory_dff7 {
  strings:
    $key_dff7 = { 88 85 [2] ba a7 [2] bc 92 [2] 92 92 [2] ad 8e }

  condition:
    any of them
}