rule TTP_XOR_WriteProcessMemory_e10b {
  strings:
    $key_e10b = { b6 79 [2] 84 5b [2] 82 6e [2] ac 6e [2] 93 72 }

  condition:
    any of them
}