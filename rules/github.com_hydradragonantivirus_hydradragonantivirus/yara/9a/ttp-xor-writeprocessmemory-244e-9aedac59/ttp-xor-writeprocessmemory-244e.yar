rule TTP_XOR_WriteProcessMemory_244e {
  strings:
    $key_244e = { 73 3c [2] 41 1e [2] 47 2b [2] 69 2b [2] 56 37 }

  condition:
    any of them
}