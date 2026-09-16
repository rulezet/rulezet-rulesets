rule TTP_XOR_WriteProcessMemory_4a7c {
  strings:
    $key_4a7c = { 1d 0e [2] 2f 2c [2] 29 19 [2] 07 19 [2] 38 05 }

  condition:
    any of them
}