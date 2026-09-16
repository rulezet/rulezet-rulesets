rule TTP_XOR_WriteProcessMemory_e5c1 {
  strings:
    $key_e5c1 = { b2 b3 [2] 80 91 [2] 86 a4 [2] a8 a4 [2] 97 b8 }

  condition:
    any of them
}