rule TTP_XOR_WriteProcessMemory_c4e3 {
  strings:
    $key_c4e3 = { 93 91 [2] a1 b3 [2] a7 86 [2] 89 86 [2] b6 9a }

  condition:
    any of them
}