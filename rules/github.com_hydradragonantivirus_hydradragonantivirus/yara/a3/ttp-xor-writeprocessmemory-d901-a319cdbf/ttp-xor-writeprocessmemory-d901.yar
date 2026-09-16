rule TTP_XOR_WriteProcessMemory_d901 {
  strings:
    $key_d901 = { 8e 73 [2] bc 51 [2] ba 64 [2] 94 64 [2] ab 78 }

  condition:
    any of them
}