rule TTP_XOR_WriteProcessMemory_0c92 {
  strings:
    $key_0c92 = { 5b e0 [2] 69 c2 [2] 6f f7 [2] 41 f7 [2] 7e eb }

  condition:
    any of them
}