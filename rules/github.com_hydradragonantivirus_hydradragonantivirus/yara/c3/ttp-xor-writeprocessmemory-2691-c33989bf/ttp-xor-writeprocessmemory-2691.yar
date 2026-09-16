rule TTP_XOR_WriteProcessMemory_2691 {
  strings:
    $key_2691 = { 71 e3 [2] 43 c1 [2] 45 f4 [2] 6b f4 [2] 54 e8 }

  condition:
    any of them
}