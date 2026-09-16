rule TTP_XOR_WriteProcessMemory_4d1c {
  strings:
    $key_4d1c = { 1a 6e [2] 28 4c [2] 2e 79 [2] 00 79 [2] 3f 65 }

  condition:
    any of them
}