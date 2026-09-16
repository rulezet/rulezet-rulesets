rule TTP_XOR_WriteProcessMemory_4e1c {
  strings:
    $key_4e1c = { 19 6e [2] 2b 4c [2] 2d 79 [2] 03 79 [2] 3c 65 }

  condition:
    any of them
}