rule TTP_XOR_WriteProcessMemory_5c94 {
  strings:
    $key_5c94 = { 0b e6 [2] 39 c4 [2] 3f f1 [2] 11 f1 [2] 2e ed }

  condition:
    any of them
}