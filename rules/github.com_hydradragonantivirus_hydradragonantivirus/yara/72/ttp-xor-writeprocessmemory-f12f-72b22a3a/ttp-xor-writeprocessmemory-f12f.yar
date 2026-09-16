rule TTP_XOR_WriteProcessMemory_f12f {
  strings:
    $key_f12f = { a6 5d [2] 94 7f [2] 92 4a [2] bc 4a [2] 83 56 }

  condition:
    any of them
}