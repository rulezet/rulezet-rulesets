rule TTP_XOR_WriteProcessMemory_c2e8 {
  strings:
    $key_c2e8 = { 95 9a [2] a7 b8 [2] a1 8d [2] 8f 8d [2] b0 91 }

  condition:
    any of them
}