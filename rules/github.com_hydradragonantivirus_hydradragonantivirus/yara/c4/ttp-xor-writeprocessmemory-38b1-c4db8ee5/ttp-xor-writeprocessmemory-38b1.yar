rule TTP_XOR_WriteProcessMemory_38b1 {
  strings:
    $key_38b1 = { 6f c3 [2] 5d e1 [2] 5b d4 [2] 75 d4 [2] 4a c8 }

  condition:
    any of them
}