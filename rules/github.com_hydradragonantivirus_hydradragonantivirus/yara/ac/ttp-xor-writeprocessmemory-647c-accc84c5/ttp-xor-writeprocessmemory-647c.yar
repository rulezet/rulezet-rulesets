rule TTP_XOR_WriteProcessMemory_647c {
  strings:
    $key_647c = { 33 0e [2] 01 2c [2] 07 19 [2] 29 19 [2] 16 05 }

  condition:
    any of them
}