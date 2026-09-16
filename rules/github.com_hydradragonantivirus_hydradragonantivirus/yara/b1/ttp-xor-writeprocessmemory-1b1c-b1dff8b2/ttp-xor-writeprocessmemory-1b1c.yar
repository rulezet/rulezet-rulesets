rule TTP_XOR_WriteProcessMemory_1b1c {
  strings:
    $key_1b1c = { 4c 6e [2] 7e 4c [2] 78 79 [2] 56 79 [2] 69 65 }

  condition:
    any of them
}