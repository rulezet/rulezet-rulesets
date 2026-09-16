rule TTP_XOR_WriteProcessMemory_190e {
  strings:
    $key_190e = { 4e 7c [2] 7c 5e [2] 7a 6b [2] 54 6b [2] 6b 77 }

  condition:
    any of them
}