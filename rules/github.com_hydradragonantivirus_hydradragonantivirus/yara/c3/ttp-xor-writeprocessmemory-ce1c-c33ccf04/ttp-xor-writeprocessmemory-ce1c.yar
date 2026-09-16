rule TTP_XOR_WriteProcessMemory_ce1c {
  strings:
    $key_ce1c = { 99 6e [2] ab 4c [2] ad 79 [2] 83 79 [2] bc 65 }

  condition:
    any of them
}