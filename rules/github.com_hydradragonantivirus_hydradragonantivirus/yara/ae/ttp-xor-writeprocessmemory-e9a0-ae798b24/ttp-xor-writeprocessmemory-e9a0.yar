rule TTP_XOR_WriteProcessMemory_e9a0 {
  strings:
    $key_e9a0 = { be d2 [2] 8c f0 [2] 8a c5 [2] a4 c5 [2] 9b d9 }

  condition:
    any of them
}