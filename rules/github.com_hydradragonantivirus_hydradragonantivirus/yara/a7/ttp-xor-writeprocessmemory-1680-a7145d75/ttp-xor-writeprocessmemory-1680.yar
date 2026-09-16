rule TTP_XOR_WriteProcessMemory_1680 {
  strings:
    $key_1680 = { 41 f2 [2] 73 d0 [2] 75 e5 [2] 5b e5 [2] 64 f9 }

  condition:
    any of them
}