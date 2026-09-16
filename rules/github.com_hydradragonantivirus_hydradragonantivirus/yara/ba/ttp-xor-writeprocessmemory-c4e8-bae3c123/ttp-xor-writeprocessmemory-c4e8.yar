rule TTP_XOR_WriteProcessMemory_c4e8 {
  strings:
    $key_c4e8 = { 93 9a [2] a1 b8 [2] a7 8d [2] 89 8d [2] b6 91 }

  condition:
    any of them
}