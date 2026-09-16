rule TTP_XOR_WriteProcessMemory_e3b0 {
  strings:
    $key_e3b0 = { b4 c2 [2] 86 e0 [2] 80 d5 [2] ae d5 [2] 91 c9 }

  condition:
    any of them
}