rule TTP_XOR_WriteProcessMemory_e552 {
  strings:
    $key_e552 = { b2 20 [2] 80 02 [2] 86 37 [2] a8 37 [2] 97 2b }

  condition:
    any of them
}