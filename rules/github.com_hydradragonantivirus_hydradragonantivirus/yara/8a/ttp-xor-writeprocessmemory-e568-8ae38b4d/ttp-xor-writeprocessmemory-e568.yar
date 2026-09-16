rule TTP_XOR_WriteProcessMemory_e568 {
  strings:
    $key_e568 = { b2 1a [2] 80 38 [2] 86 0d [2] a8 0d [2] 97 11 }

  condition:
    any of them
}