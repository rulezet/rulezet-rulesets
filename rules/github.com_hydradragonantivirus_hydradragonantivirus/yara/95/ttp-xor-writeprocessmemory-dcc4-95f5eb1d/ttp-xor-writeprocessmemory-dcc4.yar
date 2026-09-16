rule TTP_XOR_WriteProcessMemory_dcc4 {
  strings:
    $key_dcc4 = { 8b b6 [2] b9 94 [2] bf a1 [2] 91 a1 [2] ae bd }

  condition:
    any of them
}