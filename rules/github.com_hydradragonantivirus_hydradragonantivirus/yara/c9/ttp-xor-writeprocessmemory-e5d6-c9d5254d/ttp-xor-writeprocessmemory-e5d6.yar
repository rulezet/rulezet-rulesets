rule TTP_XOR_WriteProcessMemory_e5d6 {
  strings:
    $key_e5d6 = { b2 a4 [2] 80 86 [2] 86 b3 [2] a8 b3 [2] 97 af }

  condition:
    any of them
}