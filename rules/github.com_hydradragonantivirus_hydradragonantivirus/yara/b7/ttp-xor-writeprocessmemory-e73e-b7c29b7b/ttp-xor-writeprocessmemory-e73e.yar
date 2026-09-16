rule TTP_XOR_WriteProcessMemory_e73e {
  strings:
    $key_e73e = { b0 4c [2] 82 6e [2] 84 5b [2] aa 5b [2] 95 47 }

  condition:
    any of them
}