rule TTP_XOR_WriteProcessMemory_4c92 {
  strings:
    $key_4c92 = { 1b e0 [2] 29 c2 [2] 2f f7 [2] 01 f7 [2] 3e eb }

  condition:
    any of them
}