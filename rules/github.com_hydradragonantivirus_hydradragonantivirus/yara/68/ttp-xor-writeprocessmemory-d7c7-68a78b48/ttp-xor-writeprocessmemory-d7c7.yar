rule TTP_XOR_WriteProcessMemory_d7c7 {
  strings:
    $key_d7c7 = { 80 b5 [2] b2 97 [2] b4 a2 [2] 9a a2 [2] a5 be }

  condition:
    any of them
}