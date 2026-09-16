rule TTP_XOR_WriteProcessMemory_d974 {
  strings:
    $key_d974 = { 8e 06 [2] bc 24 [2] ba 11 [2] 94 11 [2] ab 0d }

  condition:
    any of them
}