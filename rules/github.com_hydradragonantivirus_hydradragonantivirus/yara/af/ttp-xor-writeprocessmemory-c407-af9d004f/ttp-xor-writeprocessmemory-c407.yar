rule TTP_XOR_WriteProcessMemory_c407 {
  strings:
    $key_c407 = { 93 75 [2] a1 57 [2] a7 62 [2] 89 62 [2] b6 7e }

  condition:
    any of them
}