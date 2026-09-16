rule TTP_XOR_WriteProcessMemory_7c0e {
  strings:
    $key_7c0e = { 2b 7c [2] 19 5e [2] 1f 6b [2] 31 6b [2] 0e 77 }

  condition:
    any of them
}