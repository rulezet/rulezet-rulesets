rule TTP_XOR_WriteProcessMemory_531c {
  strings:
    $key_531c = { 04 6e [2] 36 4c [2] 30 79 [2] 1e 79 [2] 21 65 }

  condition:
    any of them
}