rule TTP_XOR_WriteProcessMemory_d919 {
  strings:
    $key_d919 = { 8e 6b [2] bc 49 [2] ba 7c [2] 94 7c [2] ab 60 }

  condition:
    any of them
}