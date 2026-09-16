rule TTP_XOR_WriteProcessMemory_83c9 {
  strings:
    $key_83c9 = { d4 bb [2] e6 99 [2] e0 ac [2] ce ac [2] f1 b0 }

  condition:
    any of them
}