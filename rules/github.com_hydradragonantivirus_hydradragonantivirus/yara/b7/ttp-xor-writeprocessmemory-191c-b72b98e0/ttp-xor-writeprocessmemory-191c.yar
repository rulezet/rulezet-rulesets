rule TTP_XOR_WriteProcessMemory_191c {
  strings:
    $key_191c = { 4e 6e [2] 7c 4c [2] 7a 79 [2] 54 79 [2] 6b 65 }

  condition:
    any of them
}