rule TTP_XOR_WriteProcessMemory_240e {
  strings:
    $key_240e = { 73 7c [2] 41 5e [2] 47 6b [2] 69 6b [2] 56 77 }

  condition:
    any of them
}