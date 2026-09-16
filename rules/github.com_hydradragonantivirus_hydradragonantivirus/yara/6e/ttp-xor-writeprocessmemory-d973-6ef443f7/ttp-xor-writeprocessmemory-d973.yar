rule TTP_XOR_WriteProcessMemory_d973 {
  strings:
    $key_d973 = { 8e 01 [2] bc 23 [2] ba 16 [2] 94 16 [2] ab 0a }

  condition:
    any of them
}