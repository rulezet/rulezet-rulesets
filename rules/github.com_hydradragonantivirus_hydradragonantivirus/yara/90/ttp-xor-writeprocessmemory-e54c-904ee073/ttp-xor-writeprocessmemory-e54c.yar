rule TTP_XOR_WriteProcessMemory_e54c {
  strings:
    $key_e54c = { b2 3e [2] 80 1c [2] 86 29 [2] a8 29 [2] 97 35 }

  condition:
    any of them
}