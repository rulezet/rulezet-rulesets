rule TTP_XOR_WriteProcessMemory_e50d {
  strings:
    $key_e50d = { b2 7f [2] 80 5d [2] 86 68 [2] a8 68 [2] 97 74 }

  condition:
    any of them
}