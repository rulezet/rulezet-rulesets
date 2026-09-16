rule TTP_XOR_WriteProcessMemory_28b0 {
  strings:
    $key_28b0 = { 7f c2 [2] 4d e0 [2] 4b d5 [2] 65 d5 [2] 5a c9 }

  condition:
    any of them
}