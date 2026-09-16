rule TTP_XOR_WriteProcessMemory_4aa0 {
  strings:
    $key_4aa0 = { 1d d2 [2] 2f f0 [2] 29 c5 [2] 07 c5 [2] 38 d9 }

  condition:
    any of them
}