rule TTP_XOR_WriteProcessMemory_4292 {
  strings:
    $key_4292 = { 15 e0 [2] 27 c2 [2] 21 f7 [2] 0f f7 [2] 30 eb }

  condition:
    any of them
}