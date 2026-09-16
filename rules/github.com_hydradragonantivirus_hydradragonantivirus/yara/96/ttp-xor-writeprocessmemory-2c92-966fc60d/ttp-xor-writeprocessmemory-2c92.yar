rule TTP_XOR_WriteProcessMemory_2c92 {
  strings:
    $key_2c92 = { 7b e0 [2] 49 c2 [2] 4f f7 [2] 61 f7 [2] 5e eb }

  condition:
    any of them
}