rule TTP_XOR_WriteProcessMemory_607c {
  strings:
    $key_607c = { 37 0e [2] 05 2c [2] 03 19 [2] 2d 19 [2] 12 05 }

  condition:
    any of them
}