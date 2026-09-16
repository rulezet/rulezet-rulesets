rule TTP_XOR_WriteProcessMemory_cba5 {
  strings:
    $key_cba5 = { 9c d7 [2] ae f5 [2] a8 c0 [2] 86 c0 [2] b9 dc }

  condition:
    any of them
}