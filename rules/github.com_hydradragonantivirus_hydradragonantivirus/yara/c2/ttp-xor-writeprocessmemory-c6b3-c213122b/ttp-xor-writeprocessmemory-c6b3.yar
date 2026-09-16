rule TTP_XOR_WriteProcessMemory_c6b3 {
  strings:
    $key_c6b3 = { 91 c1 [2] a3 e3 [2] a5 d6 [2] 8b d6 [2] b4 ca }

  condition:
    any of them
}