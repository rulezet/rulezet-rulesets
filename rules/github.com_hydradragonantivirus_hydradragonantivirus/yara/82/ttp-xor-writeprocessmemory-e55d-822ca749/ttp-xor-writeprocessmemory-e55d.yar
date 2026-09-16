rule TTP_XOR_WriteProcessMemory_e55d {
  strings:
    $key_e55d = { b2 2f [2] 80 0d [2] 86 38 [2] a8 38 [2] 97 24 }

  condition:
    any of them
}