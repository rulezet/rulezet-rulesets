rule TTP_XOR_WriteProcessMemory_76b4 {
  strings:
    $key_76b4 = { 21 c6 [2] 13 e4 [2] 15 d1 [2] 3b d1 [2] 04 cd }

  condition:
    any of them
}