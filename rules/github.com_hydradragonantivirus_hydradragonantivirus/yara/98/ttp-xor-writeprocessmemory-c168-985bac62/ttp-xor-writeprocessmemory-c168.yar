rule TTP_XOR_WriteProcessMemory_c168 {
  strings:
    $key_c168 = { 96 1a [2] a4 38 [2] a2 0d [2] 8c 0d [2] b3 11 }

  condition:
    any of them
}