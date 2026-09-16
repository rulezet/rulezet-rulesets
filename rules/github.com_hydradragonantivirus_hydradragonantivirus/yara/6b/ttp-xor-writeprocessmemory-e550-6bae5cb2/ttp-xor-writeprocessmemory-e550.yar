rule TTP_XOR_WriteProcessMemory_e550 {
  strings:
    $key_e550 = { b2 22 [2] 80 00 [2] 86 35 [2] a8 35 [2] 97 29 }

  condition:
    any of them
}