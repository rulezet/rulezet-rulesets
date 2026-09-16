rule TTP_XOR_WriteProcessMemory_1c92 {
  strings:
    $key_1c92 = { 4b e0 [2] 79 c2 [2] 7f f7 [2] 51 f7 [2] 6e eb }

  condition:
    any of them
}