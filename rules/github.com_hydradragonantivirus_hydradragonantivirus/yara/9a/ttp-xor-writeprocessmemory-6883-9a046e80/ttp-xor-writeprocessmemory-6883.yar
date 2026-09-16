rule TTP_XOR_WriteProcessMemory_6883 {
  strings:
    $key_6883 = { 3f f1 [2] 0d d3 [2] 0b e6 [2] 25 e6 [2] 1a fa }

  condition:
    any of them
}