rule TTP_XOR_WriteProcessMemory_312e {
  strings:
    $key_312e = { 66 5c [2] 54 7e [2] 52 4b [2] 7c 4b [2] 43 57 }

  condition:
    any of them
}