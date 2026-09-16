rule TTP_XOR_WriteProcessMemory_6c92 {
  strings:
    $key_6c92 = { 3b e0 [2] 09 c2 [2] 0f f7 [2] 21 f7 [2] 1e eb }

  condition:
    any of them
}