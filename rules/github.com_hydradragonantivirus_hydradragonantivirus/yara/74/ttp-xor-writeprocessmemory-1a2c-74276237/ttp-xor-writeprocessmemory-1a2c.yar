rule TTP_XOR_WriteProcessMemory_1a2c {
  strings:
    $key_1a2c = { 4d 5e [2] 7f 7c [2] 79 49 [2] 57 49 [2] 68 55 }

  condition:
    any of them
}