rule TTP_XOR_WriteProcessMemory_0d4e {
  strings:
    $key_0d4e = { 5a 3c [2] 68 1e [2] 6e 2b [2] 40 2b [2] 7f 37 }

  condition:
    any of them
}