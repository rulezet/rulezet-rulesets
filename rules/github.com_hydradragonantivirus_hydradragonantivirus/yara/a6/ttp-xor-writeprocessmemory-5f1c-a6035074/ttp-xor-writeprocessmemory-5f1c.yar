rule TTP_XOR_WriteProcessMemory_5f1c {
  strings:
    $key_5f1c = { 08 6e [2] 3a 4c [2] 3c 79 [2] 12 79 [2] 2d 65 }

  condition:
    any of them
}