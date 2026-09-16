rule TTP_XOR_WriteProcessMemory_cba3 {
  strings:
    $key_cba3 = { 9c d1 [2] ae f3 [2] a8 c6 [2] 86 c6 [2] b9 da }

  condition:
    any of them
}