rule TTP_XOR_WriteProcessMemory_6680 {
  strings:
    $key_6680 = { 31 f2 [2] 03 d0 [2] 05 e5 [2] 2b e5 [2] 14 f9 }

  condition:
    any of them
}