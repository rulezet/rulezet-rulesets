rule TTP_XOR_WriteProcessMemory_ce0a {
  strings:
    $key_ce0a = { 99 78 [2] ab 5a [2] ad 6f [2] 83 6f [2] bc 73 }

  condition:
    any of them
}