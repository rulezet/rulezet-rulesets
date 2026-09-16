rule TTP_XOR_WriteProcessMemory_477c {
  strings:
    $key_477c = { 10 0e [2] 22 2c [2] 24 19 [2] 0a 19 [2] 35 05 }

  condition:
    any of them
}