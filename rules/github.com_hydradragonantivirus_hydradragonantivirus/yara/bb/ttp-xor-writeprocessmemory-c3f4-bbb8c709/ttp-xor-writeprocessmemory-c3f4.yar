rule TTP_XOR_WriteProcessMemory_c3f4 {
  strings:
    $key_c3f4 = { 94 86 [2] a6 a4 [2] a0 91 [2] 8e 91 [2] b1 8d }

  condition:
    any of them
}