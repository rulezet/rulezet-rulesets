rule TTP_XOR_WriteProcessMemory_e516 {
  strings:
    $key_e516 = { b2 64 [2] 80 46 [2] 86 73 [2] a8 73 [2] 97 6f }

  condition:
    any of them
}