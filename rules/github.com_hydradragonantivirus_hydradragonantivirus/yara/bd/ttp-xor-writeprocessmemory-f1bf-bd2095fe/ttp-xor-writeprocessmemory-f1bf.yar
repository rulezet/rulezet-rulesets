rule TTP_XOR_WriteProcessMemory_f1bf {
  strings:
    $key_f1bf = { a6 cd [2] 94 ef [2] 92 da [2] bc da [2] 83 c6 }

  condition:
    any of them
}