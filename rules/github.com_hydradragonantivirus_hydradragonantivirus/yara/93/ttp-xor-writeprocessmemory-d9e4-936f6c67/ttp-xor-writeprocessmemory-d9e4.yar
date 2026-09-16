rule TTP_XOR_WriteProcessMemory_d9e4 {
  strings:
    $key_d9e4 = { 8e 96 [2] bc b4 [2] ba 81 [2] 94 81 [2] ab 9d }

  condition:
    any of them
}