rule TTP_XOR_WriteProcessMemory_ced7 {
  strings:
    $key_ced7 = { 99 a5 [2] ab 87 [2] ad b2 [2] 83 b2 [2] bc ae }

  condition:
    any of them
}