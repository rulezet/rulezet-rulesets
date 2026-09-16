rule TTP_XOR_WriteProcessMemory_7e7c {
  strings:
    $key_7e7c = { 29 0e [2] 1b 2c [2] 1d 19 [2] 33 19 [2] 0c 05 }

  condition:
    any of them
}