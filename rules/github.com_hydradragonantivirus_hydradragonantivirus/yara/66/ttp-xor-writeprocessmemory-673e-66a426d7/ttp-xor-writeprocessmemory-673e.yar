rule TTP_XOR_WriteProcessMemory_673e {
  strings:
    $key_673e = { 30 4c [2] 02 6e [2] 04 5b [2] 2a 5b [2] 15 47 }

  condition:
    any of them
}