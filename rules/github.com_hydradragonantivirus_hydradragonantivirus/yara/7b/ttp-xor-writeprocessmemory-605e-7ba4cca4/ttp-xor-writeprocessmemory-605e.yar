rule TTP_XOR_WriteProcessMemory_605e {
  strings:
    $key_605e = { 37 2c [2] 05 0e [2] 03 3b [2] 2d 3b [2] 12 27 }

  condition:
    any of them
}