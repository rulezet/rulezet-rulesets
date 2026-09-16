rule TTP_XOR_WriteProcessMemory_c543 {
  strings:
    $key_c543 = { 92 31 [2] a0 13 [2] a6 26 [2] 88 26 [2] b7 3a }

  condition:
    any of them
}