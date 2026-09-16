rule TTP_XOR_WriteProcessMemory_2b0e {
  strings:
    $key_2b0e = { 7c 7c [2] 4e 5e [2] 48 6b [2] 66 6b [2] 59 77 }

  condition:
    any of them
}