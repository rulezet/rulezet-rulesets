rule TTP_XOR_WriteProcessMemory_c585 {
  strings:
    $key_c585 = { 92 f7 [2] a0 d5 [2] a6 e0 [2] 88 e0 [2] b7 fc }

  condition:
    any of them
}