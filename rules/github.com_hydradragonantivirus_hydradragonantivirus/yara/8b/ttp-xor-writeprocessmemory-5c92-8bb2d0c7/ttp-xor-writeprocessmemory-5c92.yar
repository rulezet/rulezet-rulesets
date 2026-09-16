rule TTP_XOR_WriteProcessMemory_5c92 {
  strings:
    $key_5c92 = { 0b e0 [2] 39 c2 [2] 3f f7 [2] 11 f7 [2] 2e eb }

  condition:
    any of them
}