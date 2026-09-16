rule TTP_XOR_WriteProcessMemory_f17a {
  strings:
    $key_f17a = { a6 08 [2] 94 2a [2] 92 1f [2] bc 1f [2] 83 03 }

  condition:
    any of them
}