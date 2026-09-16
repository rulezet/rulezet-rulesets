rule TTP_XOR_WriteProcessMemory_29ce {
  strings:
    $key_29ce = { 7e bc [2] 4c 9e [2] 4a ab [2] 64 ab [2] 5b b7 }

  condition:
    any of them
}