rule TTP_XOR_WriteProcessMemory_204e {
  strings:
    $key_204e = { 77 3c [2] 45 1e [2] 43 2b [2] 6d 2b [2] 52 37 }

  condition:
    any of them
}