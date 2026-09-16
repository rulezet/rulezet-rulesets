rule TTP_XOR_WriteProcessMemory_c6a2 {
  strings:
    $key_c6a2 = { 91 d0 [2] a3 f2 [2] a5 c7 [2] 8b c7 [2] b4 db }

  condition:
    any of them
}