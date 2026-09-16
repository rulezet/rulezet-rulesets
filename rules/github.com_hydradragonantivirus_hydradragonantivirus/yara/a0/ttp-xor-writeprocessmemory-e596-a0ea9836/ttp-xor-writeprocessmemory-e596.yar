rule TTP_XOR_WriteProcessMemory_e596 {
  strings:
    $key_e596 = { b2 e4 [2] 80 c6 [2] 86 f3 [2] a8 f3 [2] 97 ef }

  condition:
    any of them
}