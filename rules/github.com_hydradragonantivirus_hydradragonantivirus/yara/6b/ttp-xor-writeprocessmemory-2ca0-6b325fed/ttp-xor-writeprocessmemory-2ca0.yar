rule TTP_XOR_WriteProcessMemory_2ca0 {
  strings:
    $key_2ca0 = { 7b d2 [2] 49 f0 [2] 4f c5 [2] 61 c5 [2] 5e d9 }

  condition:
    any of them
}