rule TTP_XOR_WriteProcessMemory_c6a4 {
  strings:
    $key_c6a4 = { 91 d6 [2] a3 f4 [2] a5 c1 [2] 8b c1 [2] b4 dd }

  condition:
    any of them
}