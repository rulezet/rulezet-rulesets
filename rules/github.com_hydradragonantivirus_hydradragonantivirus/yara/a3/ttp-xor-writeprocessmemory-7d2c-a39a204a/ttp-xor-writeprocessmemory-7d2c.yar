rule TTP_XOR_WriteProcessMemory_7d2c {
  strings:
    $key_7d2c = { 2a 5e [2] 18 7c [2] 1e 49 [2] 30 49 [2] 0f 55 }

  condition:
    any of them
}