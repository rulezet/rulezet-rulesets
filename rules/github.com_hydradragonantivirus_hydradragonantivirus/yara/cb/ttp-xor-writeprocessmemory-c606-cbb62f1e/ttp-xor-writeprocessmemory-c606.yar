rule TTP_XOR_WriteProcessMemory_c606 {
  strings:
    $key_c606 = { 91 74 [2] a3 56 [2] a5 63 [2] 8b 63 [2] b4 7f }

  condition:
    any of them
}