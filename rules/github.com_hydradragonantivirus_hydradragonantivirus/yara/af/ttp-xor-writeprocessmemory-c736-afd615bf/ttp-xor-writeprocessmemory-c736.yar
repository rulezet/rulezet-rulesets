rule TTP_XOR_WriteProcessMemory_c736 {
  strings:
    $key_c736 = { 90 44 [2] a2 66 [2] a4 53 [2] 8a 53 [2] b5 4f }

  condition:
    any of them
}