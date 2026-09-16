rule TTP_XOR_WriteProcessMemory_d970 {
  strings:
    $key_d970 = { 8e 02 [2] bc 20 [2] ba 15 [2] 94 15 [2] ab 09 }

  condition:
    any of them
}