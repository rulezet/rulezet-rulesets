rule TTP_XOR_WriteProcessMemory_d959 {
  strings:
    $key_d959 = { 8e 2b [2] bc 09 [2] ba 3c [2] 94 3c [2] ab 20 }

  condition:
    any of them
}