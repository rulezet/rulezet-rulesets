rule TTP_XOR_WriteProcessMemory_570c {
  strings:
    $key_570c = { 00 7e [2] 32 5c [2] 34 69 [2] 1a 69 [2] 25 75 }

  condition:
    any of them
}