rule TTP_XOR_WriteProcessMemory_740e {
  strings:
    $key_740e = { 23 7c [2] 11 5e [2] 17 6b [2] 39 6b [2] 06 77 }

  condition:
    any of them
}