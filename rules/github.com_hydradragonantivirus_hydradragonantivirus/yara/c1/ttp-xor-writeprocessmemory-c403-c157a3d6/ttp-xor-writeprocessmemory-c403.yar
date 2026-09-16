rule TTP_XOR_WriteProcessMemory_c403 {
  strings:
    $key_c403 = { 93 71 [2] a1 53 [2] a7 66 [2] 89 66 [2] b6 7a }

  condition:
    any of them
}