rule TTP_XOR_WriteProcessMemory_5a0e {
  strings:
    $key_5a0e = { 0d 7c [2] 3f 5e [2] 39 6b [2] 17 6b [2] 28 77 }

  condition:
    any of them
}