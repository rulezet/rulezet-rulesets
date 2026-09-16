rule TTP_XOR_WriteProcessMemory_d966 {
  strings:
    $key_d966 = { 8e 14 [2] bc 36 [2] ba 03 [2] 94 03 [2] ab 1f }

  condition:
    any of them
}