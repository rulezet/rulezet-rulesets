rule TTP_XOR_WriteProcessMemory_ce5f {
  strings:
    $key_ce5f = { 99 2d [2] ab 0f [2] ad 3a [2] 83 3a [2] bc 26 }

  condition:
    any of them
}