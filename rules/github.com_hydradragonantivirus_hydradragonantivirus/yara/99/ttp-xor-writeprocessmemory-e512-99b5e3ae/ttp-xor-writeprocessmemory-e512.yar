rule TTP_XOR_WriteProcessMemory_e512 {
  strings:
    $key_e512 = { b2 60 [2] 80 42 [2] 86 77 [2] a8 77 [2] 97 6b }

  condition:
    any of them
}