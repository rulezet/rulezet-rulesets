rule TTP_XOR_WriteProcessMemory_dfe4 {
  strings:
    $key_dfe4 = { 88 96 [2] ba b4 [2] bc 81 [2] 92 81 [2] ad 9d }

  condition:
    any of them
}