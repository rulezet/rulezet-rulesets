rule TTP_XOR_WriteProcessMemory_c473 {
  strings:
    $key_c473 = { 93 01 [2] a1 23 [2] a7 16 [2] 89 16 [2] b6 0a }

  condition:
    any of them
}