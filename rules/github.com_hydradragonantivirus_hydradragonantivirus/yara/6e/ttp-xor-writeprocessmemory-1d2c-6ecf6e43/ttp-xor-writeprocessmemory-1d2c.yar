rule TTP_XOR_WriteProcessMemory_1d2c {
  strings:
    $key_1d2c = { 4a 5e [2] 78 7c [2] 7e 49 [2] 50 49 [2] 6f 55 }

  condition:
    any of them
}