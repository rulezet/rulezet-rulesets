rule TTP_XOR_WriteProcessMemory_274c {
  strings:
    $key_274c = { 70 3e [2] 42 1c [2] 44 29 [2] 6a 29 [2] 55 35 }

  condition:
    any of them
}