rule TTP_XOR_WriteProcessMemory_d937 {
  strings:
    $key_d937 = { 8e 45 [2] bc 67 [2] ba 52 [2] 94 52 [2] ab 4e }

  condition:
    any of them
}