rule TTP_XOR_WriteProcessMemory_ce4a {
  strings:
    $key_ce4a = { 99 38 [2] ab 1a [2] ad 2f [2] 83 2f [2] bc 33 }

  condition:
    any of them
}