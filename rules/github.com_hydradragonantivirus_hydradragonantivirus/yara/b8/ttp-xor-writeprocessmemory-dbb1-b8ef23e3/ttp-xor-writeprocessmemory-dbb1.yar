rule TTP_XOR_WriteProcessMemory_dbb1 {
  strings:
    $key_dbb1 = { 8c c3 [2] be e1 [2] b8 d4 [2] 96 d4 [2] a9 c8 }

  condition:
    any of them
}