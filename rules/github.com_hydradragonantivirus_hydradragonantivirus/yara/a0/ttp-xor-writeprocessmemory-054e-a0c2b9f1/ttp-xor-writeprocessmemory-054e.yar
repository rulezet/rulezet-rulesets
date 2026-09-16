rule TTP_XOR_WriteProcessMemory_054e {
  strings:
    $key_054e = { 52 3c [2] 60 1e [2] 66 2b [2] 48 2b [2] 77 37 }

  condition:
    any of them
}