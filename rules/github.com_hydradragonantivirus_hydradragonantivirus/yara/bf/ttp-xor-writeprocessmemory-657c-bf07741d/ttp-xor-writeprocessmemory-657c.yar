rule TTP_XOR_WriteProcessMemory_657c {
  strings:
    $key_657c = { 32 0e [2] 00 2c [2] 06 19 [2] 28 19 [2] 17 05 }

  condition:
    any of them
}