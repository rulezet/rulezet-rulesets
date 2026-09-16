rule TTP_XOR_WriteProcessMemory_2680 {
  strings:
    $key_2680 = { 71 f2 [2] 43 d0 [2] 45 e5 [2] 6b e5 [2] 54 f9 }

  condition:
    any of them
}