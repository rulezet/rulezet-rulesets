rule TTP_XOR_WriteProcessMemory_7b2c {
  strings:
    $key_7b2c = { 2c 5e [2] 1e 7c [2] 18 49 [2] 36 49 [2] 09 55 }

  condition:
    any of them
}