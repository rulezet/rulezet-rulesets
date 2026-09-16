rule TTP_XOR_WriteProcessMemory_611c {
  strings:
    $key_611c = { 36 6e [2] 04 4c [2] 02 79 [2] 2c 79 [2] 13 65 }

  condition:
    any of them
}