rule TTP_XOR_WriteProcessMemory_104e {
  strings:
    $key_104e = { 47 3c [2] 75 1e [2] 73 2b [2] 5d 2b [2] 62 37 }

  condition:
    any of them
}