rule TTP_XOR_WriteProcessMemory_d993 {
  strings:
    $key_d993 = { 8e e1 [2] bc c3 [2] ba f6 [2] 94 f6 [2] ab ea }

  condition:
    any of them
}