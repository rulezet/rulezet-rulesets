rule TTP_XOR_WriteProcessMemory_d9b9 {
  strings:
    $key_d9b9 = { 8e cb [2] bc e9 [2] ba dc [2] 94 dc [2] ab c0 }

  condition:
    any of them
}