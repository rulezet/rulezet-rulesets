rule TTP_XOR_WriteProcessMemory_55b0 {
  strings:
    $key_55b0 = { 02 c2 [2] 30 e0 [2] 36 d5 [2] 18 d5 [2] 27 c9 }

  condition:
    any of them
}