rule TTP_XOR_WriteProcessMemory_e71c {
  strings:
    $key_e71c = { b0 6e [2] 82 4c [2] 84 79 [2] aa 79 [2] 95 65 }

  condition:
    any of them
}