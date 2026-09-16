rule TTP_XOR_WriteProcessMemory_0da5 {
  strings:
    $key_0da5 = { 5a d7 [2] 68 f5 [2] 6e c0 [2] 40 c0 [2] 7f dc }

  condition:
    any of them
}