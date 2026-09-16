rule TTP_XOR_WriteProcessMemory_c124 {
  strings:
    $key_c124 = { 96 56 [2] a4 74 [2] a2 41 [2] 8c 41 [2] b3 5d }

  condition:
    any of them
}