rule TTP_XOR_WriteProcessMemory_0c4e {
  strings:
    $key_0c4e = { 5b 3c [2] 69 1e [2] 6f 2b [2] 41 2b [2] 7e 37 }

  condition:
    any of them
}