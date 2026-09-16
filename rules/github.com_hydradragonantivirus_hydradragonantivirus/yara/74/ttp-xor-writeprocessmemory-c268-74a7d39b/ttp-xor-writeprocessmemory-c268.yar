rule TTP_XOR_WriteProcessMemory_c268 {
  strings:
    $key_c268 = { 95 1a [2] a7 38 [2] a1 0d [2] 8f 0d [2] b0 11 }

  condition:
    any of them
}