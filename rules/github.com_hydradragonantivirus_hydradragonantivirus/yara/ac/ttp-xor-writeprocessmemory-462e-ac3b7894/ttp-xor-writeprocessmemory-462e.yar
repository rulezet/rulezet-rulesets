rule TTP_XOR_WriteProcessMemory_462e {
  strings:
    $key_462e = { 11 5c [2] 23 7e [2] 25 4b [2] 0b 4b [2] 34 57 }

  condition:
    any of them
}