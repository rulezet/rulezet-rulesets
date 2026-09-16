rule TTP_XOR_WriteProcessMemory_f18b {
  strings:
    $key_f18b = { a6 f9 [2] 94 db [2] 92 ee [2] bc ee [2] 83 f2 }

  condition:
    any of them
}