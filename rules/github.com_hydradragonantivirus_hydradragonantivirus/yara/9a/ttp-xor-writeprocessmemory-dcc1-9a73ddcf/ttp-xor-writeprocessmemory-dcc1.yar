rule TTP_XOR_WriteProcessMemory_dcc1 {
  strings:
    $key_dcc1 = { 8b b3 [2] b9 91 [2] bf a4 [2] 91 a4 [2] ae b8 }

  condition:
    any of them
}