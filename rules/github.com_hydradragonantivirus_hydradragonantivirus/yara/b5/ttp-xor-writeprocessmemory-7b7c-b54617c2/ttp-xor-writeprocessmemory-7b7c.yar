rule TTP_XOR_WriteProcessMemory_7b7c {
  strings:
    $key_7b7c = { 2c 0e [2] 1e 2c [2] 18 19 [2] 36 19 [2] 09 05 }

  condition:
    any of them
}