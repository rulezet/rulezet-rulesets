rule TTP_XOR_WriteProcessMemory_0dd7 {
  strings:
    $key_0dd7 = { 5a a5 [2] 68 87 [2] 6e b2 [2] 40 b2 [2] 7f ae }

  condition:
    any of them
}