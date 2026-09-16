rule TTP_XOR_WriteProcessMemory_e74e {
  strings:
    $key_e74e = { b0 3c [2] 82 1e [2] 84 2b [2] aa 2b [2] 95 37 }

  condition:
    any of them
}