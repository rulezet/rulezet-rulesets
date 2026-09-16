rule TTP_XOR_WriteProcessMemory_631c {
  strings:
    $key_631c = { 34 6e [2] 06 4c [2] 00 79 [2] 2e 79 [2] 11 65 }

  condition:
    any of them
}