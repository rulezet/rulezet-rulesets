rule TTP_XOR_WriteProcessMemory_0da0 {
  strings:
    $key_0da0 = { 5a d2 [2] 68 f0 [2] 6e c5 [2] 40 c5 [2] 7f d9 }

  condition:
    any of them
}