rule TTP_XOR_WriteProcessMemory_ce4d {
  strings:
    $key_ce4d = { 99 3f [2] ab 1d [2] ad 28 [2] 83 28 [2] bc 34 }

  condition:
    any of them
}