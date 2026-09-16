rule TTP_XOR_WriteProcessMemory_e390 {
  strings:
    $key_e390 = { b4 e2 [2] 86 c0 [2] 80 f5 [2] ae f5 [2] 91 e9 }

  condition:
    any of them
}