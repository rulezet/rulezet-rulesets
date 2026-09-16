rule TTP_XOR_WriteProcessMemory_c368 {
  strings:
    $key_c368 = { 94 1a [2] a6 38 [2] a0 0d [2] 8e 0d [2] b1 11 }

  condition:
    any of them
}