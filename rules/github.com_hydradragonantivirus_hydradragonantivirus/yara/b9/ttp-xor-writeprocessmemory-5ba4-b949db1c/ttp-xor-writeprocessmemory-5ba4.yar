rule TTP_XOR_WriteProcessMemory_5ba4 {
  strings:
    $key_5ba4 = { 0c d6 [2] 3e f4 [2] 38 c1 [2] 16 c1 [2] 29 dd }

  condition:
    any of them
}