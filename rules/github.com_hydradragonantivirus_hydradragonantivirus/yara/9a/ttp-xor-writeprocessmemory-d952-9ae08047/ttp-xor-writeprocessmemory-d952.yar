rule TTP_XOR_WriteProcessMemory_d952 {
  strings:
    $key_d952 = { 8e 20 [2] bc 02 [2] ba 37 [2] 94 37 [2] ab 2b }

  condition:
    any of them
}