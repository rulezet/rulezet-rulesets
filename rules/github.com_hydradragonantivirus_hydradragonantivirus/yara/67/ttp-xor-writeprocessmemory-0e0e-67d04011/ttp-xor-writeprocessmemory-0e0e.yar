rule TTP_XOR_WriteProcessMemory_0e0e {
  strings:
    $key_0e0e = { 59 7c [2] 6b 5e [2] 6d 6b [2] 43 6b [2] 7c 77 }

  condition:
    any of them
}