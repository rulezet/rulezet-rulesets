rule TTP_XOR_WriteProcessMemory_d778 {
  strings:
    $key_d778 = { 80 0a [2] b2 28 [2] b4 1d [2] 9a 1d [2] a5 01 }

  condition:
    any of them
}