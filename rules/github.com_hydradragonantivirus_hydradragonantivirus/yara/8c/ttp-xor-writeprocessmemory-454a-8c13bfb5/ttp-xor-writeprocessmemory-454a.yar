rule TTP_XOR_WriteProcessMemory_454a {
  strings:
    $key_454a = { 12 38 [2] 20 1a [2] 26 2f [2] 08 2f [2] 37 33 }

  condition:
    any of them
}