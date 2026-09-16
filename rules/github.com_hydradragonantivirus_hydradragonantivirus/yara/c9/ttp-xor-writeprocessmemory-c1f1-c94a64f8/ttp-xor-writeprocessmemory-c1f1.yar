rule TTP_XOR_WriteProcessMemory_c1f1 {
  strings:
    $key_c1f1 = { 96 83 [2] a4 a1 [2] a2 94 [2] 8c 94 [2] b3 88 }

  condition:
    any of them
}