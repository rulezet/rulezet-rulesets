rule TTP_XOR_WriteProcessMemory_203e {
  strings:
    $key_203e = { 77 4c [2] 45 6e [2] 43 5b [2] 6d 5b [2] 52 47 }

  condition:
    any of them
}