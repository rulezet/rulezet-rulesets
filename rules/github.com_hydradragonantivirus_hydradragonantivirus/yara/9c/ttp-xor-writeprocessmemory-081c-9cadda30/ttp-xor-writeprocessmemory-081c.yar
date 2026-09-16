rule TTP_XOR_WriteProcessMemory_081c {
  strings:
    $key_081c = { 5f 6e [2] 6d 4c [2] 6b 79 [2] 45 79 [2] 7a 65 }

  condition:
    any of them
}