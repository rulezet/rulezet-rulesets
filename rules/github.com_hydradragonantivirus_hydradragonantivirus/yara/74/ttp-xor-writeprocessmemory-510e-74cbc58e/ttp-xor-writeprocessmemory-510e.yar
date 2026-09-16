rule TTP_XOR_WriteProcessMemory_510e {
  strings:
    $key_510e = { 06 7c [2] 34 5e [2] 32 6b [2] 1c 6b [2] 23 77 }

  condition:
    any of them
}