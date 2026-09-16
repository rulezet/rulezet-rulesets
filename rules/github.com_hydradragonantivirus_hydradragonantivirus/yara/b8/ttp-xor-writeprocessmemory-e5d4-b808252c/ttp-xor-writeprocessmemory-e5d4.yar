rule TTP_XOR_WriteProcessMemory_e5d4 {
  strings:
    $key_e5d4 = { b2 a6 [2] 80 84 [2] 86 b1 [2] a8 b1 [2] 97 ad }

  condition:
    any of them
}