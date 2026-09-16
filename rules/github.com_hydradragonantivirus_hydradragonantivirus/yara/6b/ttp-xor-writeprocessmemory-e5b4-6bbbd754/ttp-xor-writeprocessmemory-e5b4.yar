rule TTP_XOR_WriteProcessMemory_e5b4 {
  strings:
    $key_e5b4 = { b2 c6 [2] 80 e4 [2] 86 d1 [2] a8 d1 [2] 97 cd }

  condition:
    any of them
}