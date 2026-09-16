rule TTP_XOR_WriteProcessMemory_d916 {
  strings:
    $key_d916 = { 8e 64 [2] bc 46 [2] ba 73 [2] 94 73 [2] ab 6f }

  condition:
    any of them
}