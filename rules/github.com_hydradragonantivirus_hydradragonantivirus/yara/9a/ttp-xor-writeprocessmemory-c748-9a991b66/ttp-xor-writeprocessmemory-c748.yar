rule TTP_XOR_WriteProcessMemory_c748 {
  strings:
    $key_c748 = { 90 3a [2] a2 18 [2] a4 2d [2] 8a 2d [2] b5 31 }

  condition:
    any of them
}