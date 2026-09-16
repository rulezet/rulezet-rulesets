rule TTP_XOR_WriteProcessMemory_4492 {
  strings:
    $key_4492 = { 13 e0 [2] 21 c2 [2] 27 f7 [2] 09 f7 [2] 36 eb }

  condition:
    any of them
}