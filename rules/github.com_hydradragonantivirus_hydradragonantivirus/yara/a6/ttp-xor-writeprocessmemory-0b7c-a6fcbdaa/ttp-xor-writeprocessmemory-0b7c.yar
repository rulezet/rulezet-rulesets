rule TTP_XOR_WriteProcessMemory_0b7c {
  strings:
    $key_0b7c = { 5c 0e [2] 6e 2c [2] 68 19 [2] 46 19 [2] 79 05 }

  condition:
    any of them
}