rule TTP_XOR_WriteProcessMemory_f1af {
  strings:
    $key_f1af = { a6 dd [2] 94 ff [2] 92 ca [2] bc ca [2] 83 d6 }

  condition:
    any of them
}