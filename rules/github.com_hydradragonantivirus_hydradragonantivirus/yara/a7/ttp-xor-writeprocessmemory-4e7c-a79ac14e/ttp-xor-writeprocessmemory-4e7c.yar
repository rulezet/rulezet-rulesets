rule TTP_XOR_WriteProcessMemory_4e7c {
  strings:
    $key_4e7c = { 19 0e [2] 2b 2c [2] 2d 19 [2] 03 19 [2] 3c 05 }

  condition:
    any of them
}