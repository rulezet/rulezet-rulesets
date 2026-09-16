rule TTP_XOR_WriteProcessMemory_f1ea {
  strings:
    $key_f1ea = { a6 98 [2] 94 ba [2] 92 8f [2] bc 8f [2] 83 93 }

  condition:
    any of them
}