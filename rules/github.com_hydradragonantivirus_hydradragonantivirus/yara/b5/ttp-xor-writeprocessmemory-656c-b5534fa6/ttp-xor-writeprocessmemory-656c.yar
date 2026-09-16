rule TTP_XOR_WriteProcessMemory_656c {
  strings:
    $key_656c = { 32 1e [2] 00 3c [2] 06 09 [2] 28 09 [2] 17 15 }

  condition:
    any of them
}