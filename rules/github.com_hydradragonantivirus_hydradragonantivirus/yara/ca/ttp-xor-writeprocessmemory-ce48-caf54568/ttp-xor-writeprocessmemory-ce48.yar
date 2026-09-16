rule TTP_XOR_WriteProcessMemory_ce48 {
  strings:
    $key_ce48 = { 99 3a [2] ab 18 [2] ad 2d [2] 83 2d [2] bc 31 }

  condition:
    any of them
}