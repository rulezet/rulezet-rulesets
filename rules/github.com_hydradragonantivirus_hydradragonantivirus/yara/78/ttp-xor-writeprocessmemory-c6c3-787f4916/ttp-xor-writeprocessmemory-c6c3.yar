rule TTP_XOR_WriteProcessMemory_c6c3 {
  strings:
    $key_c6c3 = { 91 b1 [2] a3 93 [2] a5 a6 [2] 8b a6 [2] b4 ba }

  condition:
    any of them
}