rule TTP_XOR_WriteProcessMemory_2d0e {
  strings:
    $key_2d0e = { 7a 7c [2] 48 5e [2] 4e 6b [2] 60 6b [2] 5f 77 }

  condition:
    any of them
}