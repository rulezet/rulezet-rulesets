rule TTP_XOR_WriteProcessMemory_056c {
  strings:
    $key_056c = { 52 1e [2] 60 3c [2] 66 09 [2] 48 09 [2] 77 15 }

  condition:
    any of them
}