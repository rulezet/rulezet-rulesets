rule TTP_XOR_WriteProcessMemory_591c {
  strings:
    $key_591c = { 0e 6e [2] 3c 4c [2] 3a 79 [2] 14 79 [2] 2b 65 }

  condition:
    any of them
}