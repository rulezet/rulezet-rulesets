rule TTP_XOR_WriteProcessMemory_e180 {
  strings:
    $key_e180 = { b6 f2 [2] 84 d0 [2] 82 e5 [2] ac e5 [2] 93 f9 }

  condition:
    any of them
}