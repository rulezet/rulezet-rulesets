rule TTP_XOR_WriteProcessMemory_ce1f {
  strings:
    $key_ce1f = { 99 6d [2] ab 4f [2] ad 7a [2] 83 7a [2] bc 66 }

  condition:
    any of them
}