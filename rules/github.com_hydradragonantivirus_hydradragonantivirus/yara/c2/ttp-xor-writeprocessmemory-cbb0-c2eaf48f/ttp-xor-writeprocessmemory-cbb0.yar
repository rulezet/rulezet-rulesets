rule TTP_XOR_WriteProcessMemory_cbb0 {
  strings:
    $key_cbb0 = { 9c c2 [2] ae e0 [2] a8 d5 [2] 86 d5 [2] b9 c9 }

  condition:
    any of them
}