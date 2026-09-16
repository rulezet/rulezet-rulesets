rule TTP_XOR_WriteProcessMemory_d2e8 {
  strings:
    $key_d2e8 = { 85 9a [2] b7 b8 [2] b1 8d [2] 9f 8d [2] a0 91 }

  condition:
    any of them
}