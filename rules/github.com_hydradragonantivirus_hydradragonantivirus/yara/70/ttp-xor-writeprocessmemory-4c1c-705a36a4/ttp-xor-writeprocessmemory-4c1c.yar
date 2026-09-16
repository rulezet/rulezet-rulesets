rule TTP_XOR_WriteProcessMemory_4c1c {
  strings:
    $key_4c1c = { 1b 6e [2] 29 4c [2] 2f 79 [2] 01 79 [2] 3e 65 }

  condition:
    any of them
}