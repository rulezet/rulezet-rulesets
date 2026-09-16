rule TTP_XOR_WriteProcessMemory_c248 {
  strings:
    $key_c248 = { 95 3a [2] a7 18 [2] a1 2d [2] 8f 2d [2] b0 31 }

  condition:
    any of them
}