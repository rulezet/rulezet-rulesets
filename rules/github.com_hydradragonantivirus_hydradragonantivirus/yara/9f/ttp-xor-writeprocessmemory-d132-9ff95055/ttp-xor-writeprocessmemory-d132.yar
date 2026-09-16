rule TTP_XOR_WriteProcessMemory_d132 {
  strings:
    $key_d132 = { 86 40 [2] b4 62 [2] b2 57 [2] 9c 57 [2] a3 4b }

  condition:
    any of them
}