rule TTP_XOR_WriteProcessMemory_1d7c {
  strings:
    $key_1d7c = { 4a 0e [2] 78 2c [2] 7e 19 [2] 50 19 [2] 6f 05 }

  condition:
    any of them
}