rule TTP_XOR_WriteProcessMemory_e14e {
  strings:
    $key_e14e = { b6 3c [2] 84 1e [2] 82 2b [2] ac 2b [2] 93 37 }

  condition:
    any of them
}