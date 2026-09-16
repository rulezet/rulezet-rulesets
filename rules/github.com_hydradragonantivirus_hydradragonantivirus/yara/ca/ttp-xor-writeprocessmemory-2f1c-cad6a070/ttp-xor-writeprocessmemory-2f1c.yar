rule TTP_XOR_WriteProcessMemory_2f1c {
  strings:
    $key_2f1c = { 78 6e [2] 4a 4c [2] 4c 79 [2] 62 79 [2] 5d 65 }

  condition:
    any of them
}