rule TTP_XOR_WriteProcessMemory_441c {
  strings:
    $key_441c = { 13 6e [2] 21 4c [2] 27 79 [2] 09 79 [2] 36 65 }

  condition:
    any of them
}