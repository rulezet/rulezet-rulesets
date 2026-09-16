rule TTP_XOR_WriteProcessMemory_ce1a {
  strings:
    $key_ce1a = { 99 68 [2] ab 4a [2] ad 7f [2] 83 7f [2] bc 63 }

  condition:
    any of them
}