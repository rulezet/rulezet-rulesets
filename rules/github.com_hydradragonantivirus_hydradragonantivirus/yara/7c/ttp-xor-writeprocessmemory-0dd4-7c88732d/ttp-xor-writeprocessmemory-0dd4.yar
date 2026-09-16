rule TTP_XOR_WriteProcessMemory_0dd4 {
  strings:
    $key_0dd4 = { 5a a6 [2] 68 84 [2] 6e b1 [2] 40 b1 [2] 7f ad }

  condition:
    any of them
}