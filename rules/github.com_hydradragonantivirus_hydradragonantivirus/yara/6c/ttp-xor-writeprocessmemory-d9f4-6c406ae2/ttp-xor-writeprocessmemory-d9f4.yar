rule TTP_XOR_WriteProcessMemory_d9f4 {
  strings:
    $key_d9f4 = { 8e 86 [2] bc a4 [2] ba 91 [2] 94 91 [2] ab 8d }

  condition:
    any of them
}