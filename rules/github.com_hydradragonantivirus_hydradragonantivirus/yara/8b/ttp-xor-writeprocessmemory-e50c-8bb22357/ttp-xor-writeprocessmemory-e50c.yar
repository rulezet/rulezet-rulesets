rule TTP_XOR_WriteProcessMemory_e50c {
  strings:
    $key_e50c = { b2 7e [2] 80 5c [2] 86 69 [2] a8 69 [2] 97 75 }

  condition:
    any of them
}