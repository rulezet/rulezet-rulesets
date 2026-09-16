rule TTP_XOR_WriteProcessMemory_c3e3 {
  strings:
    $key_c3e3 = { 94 91 [2] a6 b3 [2] a0 86 [2] 8e 86 [2] b1 9a }

  condition:
    any of them
}