rule TTP_XOR_WriteProcessMemory_d909 {
  strings:
    $key_d909 = { 8e 7b [2] bc 59 [2] ba 6c [2] 94 6c [2] ab 70 }

  condition:
    any of them
}