rule TTP_XOR_WriteProcessMemory_1c90 {
  strings:
    $key_1c90 = { 4b e2 [2] 79 c0 [2] 7f f5 [2] 51 f5 [2] 6e e9 }

  condition:
    any of them
}