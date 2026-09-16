rule TTP_XOR_WriteProcessMemory_1aa4 {
  strings:
    $key_1aa4 = { 4d d6 [2] 7f f4 [2] 79 c1 [2] 57 c1 [2] 68 dd }

  condition:
    any of them
}