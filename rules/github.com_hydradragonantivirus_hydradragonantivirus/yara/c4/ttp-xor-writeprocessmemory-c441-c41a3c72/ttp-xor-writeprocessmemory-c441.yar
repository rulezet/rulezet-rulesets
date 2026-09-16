rule TTP_XOR_WriteProcessMemory_c441 {
  strings:
    $key_c441 = { 93 33 [2] a1 11 [2] a7 24 [2] 89 24 [2] b6 38 }

  condition:
    any of them
}