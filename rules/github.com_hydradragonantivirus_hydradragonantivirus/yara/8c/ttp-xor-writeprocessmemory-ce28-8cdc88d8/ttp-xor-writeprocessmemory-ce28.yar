rule TTP_XOR_WriteProcessMemory_ce28 {
  strings:
    $key_ce28 = { 99 5a [2] ab 78 [2] ad 4d [2] 83 4d [2] bc 51 }

  condition:
    any of them
}