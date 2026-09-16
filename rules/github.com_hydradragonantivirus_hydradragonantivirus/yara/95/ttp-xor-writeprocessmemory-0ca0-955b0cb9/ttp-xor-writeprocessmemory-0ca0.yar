rule TTP_XOR_WriteProcessMemory_0ca0 {
  strings:
    $key_0ca0 = { 5b d2 [2] 69 f0 [2] 6f c5 [2] 41 c5 [2] 7e d9 }

  condition:
    any of them
}