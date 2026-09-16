rule TTP_XOR_WriteProcessMemory_7a0e {
  strings:
    $key_7a0e = { 2d 7c [2] 1f 5e [2] 19 6b [2] 37 6b [2] 08 77 }

  condition:
    any of them
}