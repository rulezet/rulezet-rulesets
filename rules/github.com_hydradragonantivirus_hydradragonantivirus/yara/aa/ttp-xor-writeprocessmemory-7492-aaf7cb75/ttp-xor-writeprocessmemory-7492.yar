rule TTP_XOR_WriteProcessMemory_7492 {
  strings:
    $key_7492 = { 23 e0 [2] 11 c2 [2] 17 f7 [2] 39 f7 [2] 06 eb }

  condition:
    any of them
}