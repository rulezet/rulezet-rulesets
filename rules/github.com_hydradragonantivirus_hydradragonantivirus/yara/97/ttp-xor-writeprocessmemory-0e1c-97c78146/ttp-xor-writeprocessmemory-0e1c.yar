rule TTP_XOR_WriteProcessMemory_0e1c {
  strings:
    $key_0e1c = { 59 6e [2] 6b 4c [2] 6d 79 [2] 43 79 [2] 7c 65 }

  condition:
    any of them
}