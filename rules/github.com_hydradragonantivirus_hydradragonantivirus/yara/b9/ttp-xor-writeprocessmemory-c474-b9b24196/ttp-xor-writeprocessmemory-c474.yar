rule TTP_XOR_WriteProcessMemory_c474 {
  strings:
    $key_c474 = { 93 06 [2] a1 24 [2] a7 11 [2] 89 11 [2] b6 0d }

  condition:
    any of them
}