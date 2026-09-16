rule TTP_XOR_WriteProcessMemory_5b2c {
  strings:
    $key_5b2c = { 0c 5e [2] 3e 7c [2] 38 49 [2] 16 49 [2] 29 55 }

  condition:
    any of them
}