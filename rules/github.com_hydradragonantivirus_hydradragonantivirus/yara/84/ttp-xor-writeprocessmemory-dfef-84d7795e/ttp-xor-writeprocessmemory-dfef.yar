rule TTP_XOR_WriteProcessMemory_dfef {
  strings:
    $key_dfef = { 88 9d [2] ba bf [2] bc 8a [2] 92 8a [2] ad 96 }

  condition:
    any of them
}