rule TTP_XOR_WriteProcessMemory_c5c7 {
  strings:
    $key_c5c7 = { 92 b5 [2] a0 97 [2] a6 a2 [2] 88 a2 [2] b7 be }

  condition:
    any of them
}