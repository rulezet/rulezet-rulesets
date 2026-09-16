rule TTP_XOR_WriteProcessMemory_ceff {
  strings:
    $key_ceff = { 99 8d [2] ab af [2] ad 9a [2] 83 9a [2] bc 86 }

  condition:
    any of them
}