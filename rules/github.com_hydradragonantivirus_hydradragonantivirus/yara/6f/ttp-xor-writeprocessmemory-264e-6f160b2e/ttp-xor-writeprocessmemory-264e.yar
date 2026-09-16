rule TTP_XOR_WriteProcessMemory_264e {
  strings:
    $key_264e = { 71 3c [2] 43 1e [2] 45 2b [2] 6b 2b [2] 54 37 }

  condition:
    any of them
}