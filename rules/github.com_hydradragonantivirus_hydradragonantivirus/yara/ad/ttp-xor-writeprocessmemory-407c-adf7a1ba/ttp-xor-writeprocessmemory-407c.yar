rule TTP_XOR_WriteProcessMemory_407c {
  strings:
    $key_407c = { 17 0e [2] 25 2c [2] 23 19 [2] 0d 19 [2] 32 05 }

  condition:
    any of them
}