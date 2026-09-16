rule TTP_XOR_WriteProcessMemory_0a0e {
  strings:
    $key_0a0e = { 5d 7c [2] 6f 5e [2] 69 6b [2] 47 6b [2] 78 77 }

  condition:
    any of them
}