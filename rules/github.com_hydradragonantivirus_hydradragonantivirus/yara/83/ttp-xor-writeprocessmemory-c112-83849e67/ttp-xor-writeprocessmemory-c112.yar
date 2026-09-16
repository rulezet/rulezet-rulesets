rule TTP_XOR_WriteProcessMemory_c112 {
  strings:
    $key_c112 = { 96 60 [2] a4 42 [2] a2 77 [2] 8c 77 [2] b3 6b }

  condition:
    any of them
}