rule TTP_XOR_WriteProcessMemory_6b0e {
  strings:
    $key_6b0e = { 3c 7c [2] 0e 5e [2] 08 6b [2] 26 6b [2] 19 77 }

  condition:
    any of them
}