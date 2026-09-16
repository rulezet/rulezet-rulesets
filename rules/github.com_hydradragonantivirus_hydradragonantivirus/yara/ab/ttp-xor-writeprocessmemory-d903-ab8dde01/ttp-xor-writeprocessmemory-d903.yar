rule TTP_XOR_WriteProcessMemory_d903 {
  strings:
    $key_d903 = { 8e 71 [2] bc 53 [2] ba 66 [2] 94 66 [2] ab 7a }

  condition:
    any of them
}