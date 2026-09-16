rule TTP_XOR_WriteProcessMemory_3e0e {
  strings:
    $key_3e0e = { 69 7c [2] 5b 5e [2] 5d 6b [2] 73 6b [2] 4c 77 }

  condition:
    any of them
}