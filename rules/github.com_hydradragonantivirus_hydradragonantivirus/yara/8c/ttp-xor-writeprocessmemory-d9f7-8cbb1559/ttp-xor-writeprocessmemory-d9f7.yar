rule TTP_XOR_WriteProcessMemory_d9f7 {
  strings:
    $key_d9f7 = { 8e 85 [2] bc a7 [2] ba 92 [2] 94 92 [2] ab 8e }

  condition:
    any of them
}