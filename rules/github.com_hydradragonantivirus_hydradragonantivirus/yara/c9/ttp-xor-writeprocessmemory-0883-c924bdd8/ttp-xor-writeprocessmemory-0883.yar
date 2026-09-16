rule TTP_XOR_WriteProcessMemory_0883 {
  strings:
    $key_0883 = { 5f f1 [2] 6d d3 [2] 6b e6 [2] 45 e6 [2] 7a fa }

  condition:
    any of them
}