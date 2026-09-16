rule TTP_XOR_WriteProcessMemory_342e {
  strings:
    $key_342e = { 63 5c [2] 51 7e [2] 57 4b [2] 79 4b [2] 46 57 }

  condition:
    any of them
}