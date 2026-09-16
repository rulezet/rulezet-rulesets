rule TTP_XOR_WriteProcessMemory_5aa4 {
  strings:
    $key_5aa4 = { 0d d6 [2] 3f f4 [2] 39 c1 [2] 17 c1 [2] 28 dd }

  condition:
    any of them
}