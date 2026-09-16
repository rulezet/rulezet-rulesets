rule TTP_XOR_WriteProcessMemory_472c {
  strings:
    $key_472c = { 10 5e [2] 22 7c [2] 24 49 [2] 0a 49 [2] 35 55 }

  condition:
    any of them
}