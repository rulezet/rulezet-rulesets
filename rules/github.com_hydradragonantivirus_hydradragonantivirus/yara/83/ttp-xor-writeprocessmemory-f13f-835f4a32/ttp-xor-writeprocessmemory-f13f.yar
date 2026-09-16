rule TTP_XOR_WriteProcessMemory_f13f {
  strings:
    $key_f13f = { a6 4d [2] 94 6f [2] 92 5a [2] bc 5a [2] 83 46 }

  condition:
    any of them
}