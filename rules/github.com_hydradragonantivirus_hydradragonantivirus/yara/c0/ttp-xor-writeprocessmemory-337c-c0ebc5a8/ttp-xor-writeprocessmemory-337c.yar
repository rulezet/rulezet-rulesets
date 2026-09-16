rule TTP_XOR_WriteProcessMemory_337c {
  strings:
    $key_337c = { 64 0e [2] 56 2c [2] 50 19 [2] 7e 19 [2] 41 05 }

  condition:
    any of them
}