rule TTP_XOR_WriteProcessMemory_c507 {
  strings:
    $key_c507 = { 92 75 [2] a0 57 [2] a6 62 [2] 88 62 [2] b7 7e }

  condition:
    any of them
}