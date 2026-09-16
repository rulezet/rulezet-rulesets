rule TTP_XOR_WriteProcessMemory_440c {
  strings:
    $key_440c = { 13 7e [2] 21 5c [2] 27 69 [2] 09 69 [2] 36 75 }

  condition:
    any of them
}