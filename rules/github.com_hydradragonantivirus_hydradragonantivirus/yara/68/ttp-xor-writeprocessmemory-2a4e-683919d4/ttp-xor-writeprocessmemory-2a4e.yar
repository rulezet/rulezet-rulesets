rule TTP_XOR_WriteProcessMemory_2a4e {
  strings:
    $key_2a4e = { 7d 3c [2] 4f 1e [2] 49 2b [2] 67 2b [2] 58 37 }

  condition:
    any of them
}