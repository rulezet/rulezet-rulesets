rule TTP_XOR_WriteProcessMemory_7f0e {
  strings:
    $key_7f0e = { 28 7c [2] 1a 5e [2] 1c 6b [2] 32 6b [2] 0d 77 }

  condition:
    any of them
}