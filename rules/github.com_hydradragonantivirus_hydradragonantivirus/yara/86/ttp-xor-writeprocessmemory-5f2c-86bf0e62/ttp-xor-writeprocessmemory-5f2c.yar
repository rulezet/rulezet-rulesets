rule TTP_XOR_WriteProcessMemory_5f2c {
  strings:
    $key_5f2c = { 08 5e [2] 3a 7c [2] 3c 49 [2] 12 49 [2] 2d 55 }

  condition:
    any of them
}