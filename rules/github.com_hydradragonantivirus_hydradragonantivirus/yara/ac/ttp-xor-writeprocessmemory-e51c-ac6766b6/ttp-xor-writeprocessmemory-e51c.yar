rule TTP_XOR_WriteProcessMemory_e51c {
  strings:
    $key_e51c = { b2 6e [2] 80 4c [2] 86 79 [2] a8 79 [2] 97 65 }

  condition:
    any of them
}