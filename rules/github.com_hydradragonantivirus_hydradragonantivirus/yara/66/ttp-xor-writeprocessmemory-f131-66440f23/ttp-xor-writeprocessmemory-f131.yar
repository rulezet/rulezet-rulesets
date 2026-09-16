rule TTP_XOR_WriteProcessMemory_f131 {
  strings:
    $key_f131 = { a6 43 [2] 94 61 [2] 92 54 [2] bc 54 [2] 83 48 }

  condition:
    any of them
}