rule TTP_XOR_WriteProcessMemory_c440 {
  strings:
    $key_c440 = { 93 32 [2] a1 10 [2] a7 25 [2] 89 25 [2] b6 39 }

  condition:
    any of them
}