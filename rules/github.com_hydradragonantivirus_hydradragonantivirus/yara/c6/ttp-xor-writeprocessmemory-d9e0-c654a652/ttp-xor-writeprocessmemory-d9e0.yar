rule TTP_XOR_WriteProcessMemory_d9e0 {
  strings:
    $key_d9e0 = { 8e 92 [2] bc b0 [2] ba 85 [2] 94 85 [2] ab 99 }

  condition:
    any of them
}