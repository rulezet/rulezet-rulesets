rule TTP_XOR_WriteProcessMemory_d796 {
  strings:
    $key_d796 = { 80 e4 [2] b2 c6 [2] b4 f3 [2] 9a f3 [2] a5 ef }

  condition:
    any of them
}