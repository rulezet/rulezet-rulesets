rule TTP_XOR_WriteProcessMemory_e70e {
  strings:
    $key_e70e = { b0 7c [2] 82 5e [2] 84 6b [2] aa 6b [2] 95 77 }

  condition:
    any of them
}