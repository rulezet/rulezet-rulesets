rule TTP_XOR_WriteProcessMemory_754e {
  strings:
    $key_754e = { 22 3c [2] 10 1e [2] 16 2b [2] 38 2b [2] 07 37 }

  condition:
    any of them
}