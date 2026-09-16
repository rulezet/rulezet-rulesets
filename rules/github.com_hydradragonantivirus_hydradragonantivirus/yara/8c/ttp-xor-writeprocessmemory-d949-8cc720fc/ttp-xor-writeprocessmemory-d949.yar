rule TTP_XOR_WriteProcessMemory_d949 {
  strings:
    $key_d949 = { 8e 3b [2] bc 19 [2] ba 2c [2] 94 2c [2] ab 30 }

  condition:
    any of them
}