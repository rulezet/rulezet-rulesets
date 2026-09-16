rule TTP_XOR_WriteProcessMemory_5b1c {
  strings:
    $key_5b1c = { 0c 6e [2] 3e 4c [2] 38 79 [2] 16 79 [2] 29 65 }

  condition:
    any of them
}