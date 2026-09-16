rule TTP_XOR_WriteProcessMemory_d943 {
  strings:
    $key_d943 = { 8e 31 [2] bc 13 [2] ba 26 [2] 94 26 [2] ab 3a }

  condition:
    any of them
}