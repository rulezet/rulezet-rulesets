rule TTP_XOR_WriteProcessMemory_c5e3 {
  strings:
    $key_c5e3 = { 92 91 [2] a0 b3 [2] a6 86 [2] 88 86 [2] b7 9a }

  condition:
    any of them
}