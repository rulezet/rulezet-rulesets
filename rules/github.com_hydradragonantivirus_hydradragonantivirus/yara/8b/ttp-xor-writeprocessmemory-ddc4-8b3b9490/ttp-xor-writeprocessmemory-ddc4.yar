rule TTP_XOR_WriteProcessMemory_ddc4 {
  strings:
    $key_ddc4 = { 8a b6 [2] b8 94 [2] be a1 [2] 90 a1 [2] af bd }

  condition:
    any of them
}