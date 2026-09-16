rule TTP_XOR_WriteProcessMemory_dff8 {
  strings:
    $key_dff8 = { 88 8a [2] ba a8 [2] bc 9d [2] 92 9d [2] ad 81 }

  condition:
    any of them
}