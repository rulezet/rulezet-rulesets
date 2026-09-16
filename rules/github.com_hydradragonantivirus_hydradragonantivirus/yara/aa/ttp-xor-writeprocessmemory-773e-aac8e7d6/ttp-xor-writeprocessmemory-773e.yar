rule TTP_XOR_WriteProcessMemory_773e {
  strings:
    $key_773e = { 20 4c [2] 12 6e [2] 14 5b [2] 3a 5b [2] 05 47 }

  condition:
    any of them
}