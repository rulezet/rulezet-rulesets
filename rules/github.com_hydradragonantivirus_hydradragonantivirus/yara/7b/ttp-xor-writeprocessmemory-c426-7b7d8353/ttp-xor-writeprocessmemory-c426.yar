rule TTP_XOR_WriteProcessMemory_c426 {
  strings:
    $key_c426 = { 93 54 [2] a1 76 [2] a7 43 [2] 89 43 [2] b6 5f }

  condition:
    any of them
}