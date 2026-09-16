rule TTP_XOR_WriteProcessMemory_c0c1 {
  strings:
    $key_c0c1 = { 97 b3 [2] a5 91 [2] a3 a4 [2] 8d a4 [2] b2 b8 }

  condition:
    any of them
}