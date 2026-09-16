rule TTP_XOR_WriteProcessMemory_c433 {
  strings:
    $key_c433 = { 93 41 [2] a1 63 [2] a7 56 [2] 89 56 [2] b6 4a }

  condition:
    any of them
}