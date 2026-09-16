rule TTP_XOR_WriteProcessMemory_072e {
  strings:
    $key_072e = { 50 5c [2] 62 7e [2] 64 4b [2] 4a 4b [2] 75 57 }

  condition:
    any of them
}