rule TTP_XOR_WriteProcessMemory_d954 {
  strings:
    $key_d954 = { 8e 26 [2] bc 04 [2] ba 31 [2] 94 31 [2] ab 2d }

  condition:
    any of them
}