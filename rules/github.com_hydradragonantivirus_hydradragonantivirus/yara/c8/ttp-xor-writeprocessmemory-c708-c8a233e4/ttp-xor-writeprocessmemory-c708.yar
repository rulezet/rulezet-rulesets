rule TTP_XOR_WriteProcessMemory_c708 {
  strings:
    $key_c708 = { 90 7a [2] a2 58 [2] a4 6d [2] 8a 6d [2] b5 71 }

  condition:
    any of them
}