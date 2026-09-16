rule TTP_XOR_WriteProcessMemory_340c {
  strings:
    $key_340c = { 63 7e [2] 51 5c [2] 57 69 [2] 79 69 [2] 46 75 }

  condition:
    any of them
}