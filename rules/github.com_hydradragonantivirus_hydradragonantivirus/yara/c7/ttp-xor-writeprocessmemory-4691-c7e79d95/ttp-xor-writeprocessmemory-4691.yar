rule TTP_XOR_WriteProcessMemory_4691 {
  strings:
    $key_4691 = { 11 e3 [2] 23 c1 [2] 25 f4 [2] 0b f4 [2] 34 e8 }

  condition:
    any of them
}