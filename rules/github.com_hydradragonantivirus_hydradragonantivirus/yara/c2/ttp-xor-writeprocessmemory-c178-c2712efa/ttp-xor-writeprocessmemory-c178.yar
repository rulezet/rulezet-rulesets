rule TTP_XOR_WriteProcessMemory_c178 {
  strings:
    $key_c178 = { 96 0a [2] a4 28 [2] a2 1d [2] 8c 1d [2] b3 01 }

  condition:
    any of them
}