rule TTP_XOR_WriteProcessMemory_091c {
  strings:
    $key_091c = { 5e 6e [2] 6c 4c [2] 6a 79 [2] 44 79 [2] 7b 65 }

  condition:
    any of them
}