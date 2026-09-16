rule TTP_XOR_WriteProcessMemory_7680 {
  strings:
    $key_7680 = { 21 f2 [2] 13 d0 [2] 15 e5 [2] 3b e5 [2] 04 f9 }

  condition:
    any of them
}