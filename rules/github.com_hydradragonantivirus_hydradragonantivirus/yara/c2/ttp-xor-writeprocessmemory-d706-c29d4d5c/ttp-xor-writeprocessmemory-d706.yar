rule TTP_XOR_WriteProcessMemory_d706 {
  strings:
    $key_d706 = { 80 74 [2] b2 56 [2] b4 63 [2] 9a 63 [2] a5 7f }

  condition:
    any of them
}