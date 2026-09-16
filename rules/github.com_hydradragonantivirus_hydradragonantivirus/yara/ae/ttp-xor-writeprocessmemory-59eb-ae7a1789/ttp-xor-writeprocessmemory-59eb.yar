rule TTP_XOR_WriteProcessMemory_59eb {
  strings:
    $key_59eb = { 0e 99 [2] 3c bb [2] 3a 8e [2] 14 8e [2] 2b 92 }

  condition:
    any of them
}