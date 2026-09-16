rule TTP_XOR_WriteProcessMemory_c682 {
  strings:
    $key_c682 = { 91 f0 [2] a3 d2 [2] a5 e7 [2] 8b e7 [2] b4 fb }

  condition:
    any of them
}