rule TTP_XOR_WriteProcessMemory_c432 {
  strings:
    $key_c432 = { 93 40 [2] a1 62 [2] a7 57 [2] 89 57 [2] b6 4b }

  condition:
    any of them
}