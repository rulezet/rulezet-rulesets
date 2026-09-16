rule TTP_XOR_WriteProcessMemory_471c {
  strings:
    $key_471c = { 10 6e [2] 22 4c [2] 24 79 [2] 0a 79 [2] 35 65 }

  condition:
    any of them
}