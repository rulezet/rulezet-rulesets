rule TTP_XOR_WriteProcessMemory_ce3a {
  strings:
    $key_ce3a = { 99 48 [2] ab 6a [2] ad 5f [2] 83 5f [2] bc 43 }

  condition:
    any of them
}