rule TTP_XOR_WriteProcessMemory_d936 {
  strings:
    $key_d936 = { 8e 44 [2] bc 66 [2] ba 53 [2] 94 53 [2] ab 4f }

  condition:
    any of them
}