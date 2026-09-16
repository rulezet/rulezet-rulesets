rule TTP_XOR_WriteProcessMemory_d9b8 {
  strings:
    $key_d9b8 = { 8e ca [2] bc e8 [2] ba dd [2] 94 dd [2] ab c1 }

  condition:
    any of them
}