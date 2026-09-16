rule TTP_XOR_WriteProcessMemory_c3e8 {
  strings:
    $key_c3e8 = { 94 9a [2] a6 b8 [2] a0 8d [2] 8e 8d [2] b1 91 }

  condition:
    any of them
}