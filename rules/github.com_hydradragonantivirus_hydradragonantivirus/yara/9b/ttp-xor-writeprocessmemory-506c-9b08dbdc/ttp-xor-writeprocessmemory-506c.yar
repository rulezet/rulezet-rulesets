rule TTP_XOR_WriteProcessMemory_506c {
  strings:
    $key_506c = { 07 1e [2] 35 3c [2] 33 09 [2] 1d 09 [2] 22 15 }

  condition:
    any of them
}