rule TTP_XOR_WriteProcessMemory_1a7c {
  strings:
    $key_1a7c = { 4d 0e [2] 7f 2c [2] 79 19 [2] 57 19 [2] 68 05 }

  condition:
    any of them
}