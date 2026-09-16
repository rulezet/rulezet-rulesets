rule TTP_XOR_WriteProcessMemory_e11c {
  strings:
    $key_e11c = { b6 6e [2] 84 4c [2] 82 79 [2] ac 79 [2] 93 65 }

  condition:
    any of them
}