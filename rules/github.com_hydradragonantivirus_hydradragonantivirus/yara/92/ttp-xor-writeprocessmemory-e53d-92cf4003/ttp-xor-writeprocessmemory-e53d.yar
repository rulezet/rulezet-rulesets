rule TTP_XOR_WriteProcessMemory_e53d {
  strings:
    $key_e53d = { b2 4f [2] 80 6d [2] 86 58 [2] a8 58 [2] 97 44 }

  condition:
    any of them
}