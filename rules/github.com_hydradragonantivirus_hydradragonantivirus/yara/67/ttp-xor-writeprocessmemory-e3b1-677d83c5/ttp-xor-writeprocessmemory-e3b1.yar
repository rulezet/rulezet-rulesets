rule TTP_XOR_WriteProcessMemory_e3b1 {
  strings:
    $key_e3b1 = { b4 c3 [2] 86 e1 [2] 80 d4 [2] ae d4 [2] 91 c8 }

  condition:
    any of them
}