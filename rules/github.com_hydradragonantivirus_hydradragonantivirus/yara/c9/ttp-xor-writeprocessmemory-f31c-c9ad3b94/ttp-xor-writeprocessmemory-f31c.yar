rule TTP_XOR_WriteProcessMemory_f31c {
  strings:
    $key_f31c = { a4 6e [2] 96 4c [2] 90 79 [2] be 79 [2] 81 65 }

  condition:
    any of them
}