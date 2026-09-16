rule TTP_XOR_WriteProcessMemory_0aa4 {
  strings:
    $key_0aa4 = { 5d d6 [2] 6f f4 [2] 69 c1 [2] 47 c1 [2] 78 dd }

  condition:
    any of them
}