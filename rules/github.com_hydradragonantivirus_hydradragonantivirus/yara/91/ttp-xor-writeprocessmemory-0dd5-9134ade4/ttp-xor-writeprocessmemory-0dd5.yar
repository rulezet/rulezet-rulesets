rule TTP_XOR_WriteProcessMemory_0dd5 {
  strings:
    $key_0dd5 = { 5a a7 [2] 68 85 [2] 6e b0 [2] 40 b0 [2] 7f ac }

  condition:
    any of them
}