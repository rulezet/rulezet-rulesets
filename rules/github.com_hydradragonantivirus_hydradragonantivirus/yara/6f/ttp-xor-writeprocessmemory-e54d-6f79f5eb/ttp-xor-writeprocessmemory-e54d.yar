rule TTP_XOR_WriteProcessMemory_e54d {
  strings:
    $key_e54d = { b2 3f [2] 80 1d [2] 86 28 [2] a8 28 [2] 97 34 }

  condition:
    any of them
}