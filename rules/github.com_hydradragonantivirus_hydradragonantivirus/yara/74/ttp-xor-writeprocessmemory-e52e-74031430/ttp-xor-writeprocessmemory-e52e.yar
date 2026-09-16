rule TTP_XOR_WriteProcessMemory_e52e {
  strings:
    $key_e52e = { b2 5c [2] 80 7e [2] 86 4b [2] a8 4b [2] 97 57 }

  condition:
    any of them
}