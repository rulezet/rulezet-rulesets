rule TTP_XOR_WriteProcessMemory_0680 {
  strings:
    $key_0680 = { 51 f2 [2] 63 d0 [2] 65 e5 [2] 4b e5 [2] 74 f9 }

  condition:
    any of them
}