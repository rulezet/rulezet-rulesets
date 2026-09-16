rule TTP_XOR_WriteProcessMemory_ce3f {
  strings:
    $key_ce3f = { 99 4d [2] ab 6f [2] ad 5a [2] 83 5a [2] bc 46 }

  condition:
    any of them
}