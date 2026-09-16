rule TTP_XOR_WriteProcessMemory_c421 {
  strings:
    $key_c421 = { 93 53 [2] a1 71 [2] a7 44 [2] 89 44 [2] b6 58 }

  condition:
    any of them
}