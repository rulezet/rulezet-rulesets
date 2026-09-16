rule TTP_XOR_WriteProcessMemory_6f1c {
  strings:
    $key_6f1c = { 38 6e [2] 0a 4c [2] 0c 79 [2] 22 79 [2] 1d 65 }

  condition:
    any of them
}