rule TTP_XOR_WriteProcessMemory_476c {
  strings:
    $key_476c = { 10 1e [2] 22 3c [2] 24 09 [2] 0a 09 [2] 35 15 }

  condition:
    any of them
}