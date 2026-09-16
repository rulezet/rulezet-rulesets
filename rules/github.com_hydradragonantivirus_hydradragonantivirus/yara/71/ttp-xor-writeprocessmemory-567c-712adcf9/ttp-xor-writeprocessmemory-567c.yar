rule TTP_XOR_WriteProcessMemory_567c {
  strings:
    $key_567c = { 01 0e [2] 33 2c [2] 35 19 [2] 1b 19 [2] 24 05 }

  condition:
    any of them
}