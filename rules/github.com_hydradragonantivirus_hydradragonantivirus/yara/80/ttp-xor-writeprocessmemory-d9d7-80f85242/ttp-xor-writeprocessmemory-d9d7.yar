rule TTP_XOR_WriteProcessMemory_d9d7 {
  strings:
    $key_d9d7 = { 8e a5 [2] bc 87 [2] ba b2 [2] 94 b2 [2] ab ae }

  condition:
    any of them
}