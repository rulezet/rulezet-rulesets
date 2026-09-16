rule TTP_XOR_WriteProcessMemory_d976 {
  strings:
    $key_d976 = { 8e 04 [2] bc 26 [2] ba 13 [2] 94 13 [2] ab 0f }

  condition:
    any of them
}