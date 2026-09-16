rule TTP_XOR_WriteProcessMemory_f1ce {
  strings:
    $key_f1ce = { a6 bc [2] 94 9e [2] 92 ab [2] bc ab [2] 83 b7 }

  condition:
    any of them
}