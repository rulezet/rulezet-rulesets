rule TTP_XOR_WriteProcessMemory_473e {
  strings:
    $key_473e = { 10 4c [2] 22 6e [2] 24 5b [2] 0a 5b [2] 35 47 }

  condition:
    any of them
}