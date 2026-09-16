rule TTP_XOR_WriteProcessMemory_f18d {
  strings:
    $key_f18d = { a6 ff [2] 94 dd [2] 92 e8 [2] bc e8 [2] 83 f4 }

  condition:
    any of them
}