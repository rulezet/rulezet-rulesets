rule TTP_XOR_WriteProcessMemory_f1ee {
  strings:
    $key_f1ee = { a6 9c [2] 94 be [2] 92 8b [2] bc 8b [2] 83 97 }

  condition:
    any of them
}