rule TTP_XOR_WriteProcessMemory_c21f {
  strings:
    $key_c21f = { 95 6d [2] a7 4f [2] a1 7a [2] 8f 7a [2] b0 66 }

  condition:
    any of them
}