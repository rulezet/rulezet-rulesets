rule TTP_XOR_WriteProcessMemory_e3a0 {
  strings:
    $key_e3a0 = { b4 d2 [2] 86 f0 [2] 80 c5 [2] ae c5 [2] 91 d9 }

  condition:
    any of them
}