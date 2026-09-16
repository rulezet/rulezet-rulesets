rule TTP_XOR_WriteProcessMemory_c7f2 {
  strings:
    $key_c7f2 = { 90 80 [2] a2 a2 [2] a4 97 [2] 8a 97 [2] b5 8b }

  condition:
    any of them
}