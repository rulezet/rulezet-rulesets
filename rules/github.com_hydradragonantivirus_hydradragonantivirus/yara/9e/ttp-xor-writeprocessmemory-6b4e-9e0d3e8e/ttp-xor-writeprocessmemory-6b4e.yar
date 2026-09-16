rule TTP_XOR_WriteProcessMemory_6b4e {
  strings:
    $key_6b4e = { 3c 3c [2] 0e 1e [2] 08 2b [2] 26 2b [2] 19 37 }

  condition:
    any of them
}