rule TTP_XOR_WriteProcessMemory_49eb {
  strings:
    $key_49eb = { 1e 99 [2] 2c bb [2] 2a 8e [2] 04 8e [2] 3b 92 }

  condition:
    any of them
}