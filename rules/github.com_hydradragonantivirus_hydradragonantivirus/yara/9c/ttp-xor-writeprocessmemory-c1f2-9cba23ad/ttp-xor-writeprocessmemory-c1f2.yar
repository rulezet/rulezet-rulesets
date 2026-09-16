rule TTP_XOR_WriteProcessMemory_c1f2 {
  strings:
    $key_c1f2 = { 96 80 [2] a4 a2 [2] a2 97 [2] 8c 97 [2] b3 8b }

  condition:
    any of them
}