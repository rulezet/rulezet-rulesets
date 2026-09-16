rule TTP_XOR_WriteProcessMemory_4d7c {
  strings:
    $key_4d7c = { 1a 0e [2] 28 2c [2] 2e 19 [2] 00 19 [2] 3f 05 }

  condition:
    any of them
}