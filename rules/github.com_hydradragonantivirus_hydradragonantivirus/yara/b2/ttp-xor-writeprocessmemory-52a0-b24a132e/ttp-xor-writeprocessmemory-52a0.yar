rule TTP_XOR_WriteProcessMemory_52a0 {
  strings:
    $key_52a0 = { 05 d2 [2] 37 f0 [2] 31 c5 [2] 1f c5 [2] 20 d9 }

  condition:
    any of them
}