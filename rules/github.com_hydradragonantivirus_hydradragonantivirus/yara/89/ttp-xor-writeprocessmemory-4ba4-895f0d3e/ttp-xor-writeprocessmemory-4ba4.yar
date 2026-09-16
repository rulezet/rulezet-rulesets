rule TTP_XOR_WriteProcessMemory_4ba4 {
  strings:
    $key_4ba4 = { 1c d6 [2] 2e f4 [2] 28 c1 [2] 06 c1 [2] 39 dd }

  condition:
    any of them
}