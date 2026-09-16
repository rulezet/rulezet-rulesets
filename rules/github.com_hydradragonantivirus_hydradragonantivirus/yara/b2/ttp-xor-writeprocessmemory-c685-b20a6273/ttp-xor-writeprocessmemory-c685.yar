rule TTP_XOR_WriteProcessMemory_c685 {
  strings:
    $key_c685 = { 91 f7 [2] a3 d5 [2] a5 e0 [2] 8b e0 [2] b4 fc }

  condition:
    any of them
}