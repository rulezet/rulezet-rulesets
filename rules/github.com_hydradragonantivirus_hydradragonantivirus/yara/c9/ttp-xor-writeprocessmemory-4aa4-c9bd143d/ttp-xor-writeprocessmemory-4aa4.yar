rule TTP_XOR_WriteProcessMemory_4aa4 {
  strings:
    $key_4aa4 = { 1d d6 [2] 2f f4 [2] 29 c1 [2] 07 c1 [2] 38 dd }

  condition:
    any of them
}