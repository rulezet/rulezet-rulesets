rule TTP_XOR_WriteProcessMemory_c478 {
  strings:
    $key_c478 = { 93 0a [2] a1 28 [2] a7 1d [2] 89 1d [2] b6 01 }

  condition:
    any of them
}