rule TTP_XOR_WriteProcessMemory_3b0e {
  strings:
    $key_3b0e = { 6c 7c [2] 5e 5e [2] 58 6b [2] 76 6b [2] 49 77 }

  condition:
    any of them
}