rule TTP_XOR_WriteProcessMemory_e191 {
  strings:
    $key_e191 = { b6 e3 [2] 84 c1 [2] 82 f4 [2] ac f4 [2] 93 e8 }

  condition:
    any of them
}