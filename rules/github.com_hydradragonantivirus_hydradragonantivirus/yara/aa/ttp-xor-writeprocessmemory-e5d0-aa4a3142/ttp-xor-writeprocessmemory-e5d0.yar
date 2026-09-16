rule TTP_XOR_WriteProcessMemory_e5d0 {
  strings:
    $key_e5d0 = { b2 a2 [2] 80 80 [2] 86 b5 [2] a8 b5 [2] 97 a9 }

  condition:
    any of them
}