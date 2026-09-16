rule TTP_XOR_WriteProcessMemory_f11a {
  strings:
    $key_f11a = { a6 68 [2] 94 4a [2] 92 7f [2] bc 7f [2] 83 63 }

  condition:
    any of them
}