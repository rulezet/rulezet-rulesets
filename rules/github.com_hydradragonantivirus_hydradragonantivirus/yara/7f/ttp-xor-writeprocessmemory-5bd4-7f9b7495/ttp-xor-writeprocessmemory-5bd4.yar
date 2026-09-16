rule TTP_XOR_WriteProcessMemory_5bd4 {
  strings:
    $key_5bd4 = { 0c a6 [2] 3e 84 [2] 38 b1 [2] 16 b1 [2] 29 ad }

  condition:
    any of them
}