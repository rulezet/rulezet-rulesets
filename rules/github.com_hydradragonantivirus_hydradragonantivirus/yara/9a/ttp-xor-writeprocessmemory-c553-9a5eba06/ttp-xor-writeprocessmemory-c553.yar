rule TTP_XOR_WriteProcessMemory_c553 {
  strings:
    $key_c553 = { 92 21 [2] a0 03 [2] a6 36 [2] 88 36 [2] b7 2a }

  condition:
    any of them
}