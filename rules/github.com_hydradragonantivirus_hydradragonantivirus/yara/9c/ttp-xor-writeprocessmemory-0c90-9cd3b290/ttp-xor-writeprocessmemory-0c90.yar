rule TTP_XOR_WriteProcessMemory_0c90 {
  strings:
    $key_0c90 = { 5b e2 [2] 69 c0 [2] 6f f5 [2] 41 f5 [2] 7e e9 }

  condition:
    any of them
}