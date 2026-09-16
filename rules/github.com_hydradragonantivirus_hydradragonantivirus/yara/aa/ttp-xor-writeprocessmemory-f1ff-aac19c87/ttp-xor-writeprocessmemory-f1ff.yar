rule TTP_XOR_WriteProcessMemory_f1ff {
  strings:
    $key_f1ff = { a6 8d [2] 94 af [2] 92 9a [2] bc 9a [2] 83 86 }

  condition:
    any of them
}