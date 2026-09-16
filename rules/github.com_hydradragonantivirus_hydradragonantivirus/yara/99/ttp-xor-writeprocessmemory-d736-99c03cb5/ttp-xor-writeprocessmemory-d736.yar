rule TTP_XOR_WriteProcessMemory_d736 {
  strings:
    $key_d736 = { 80 44 [2] b2 66 [2] b4 53 [2] 9a 53 [2] a5 4f }

  condition:
    any of them
}