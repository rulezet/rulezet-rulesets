rule TTP_XOR_WriteProcessMemory_6492 {
  strings:
    $key_6492 = { 33 e0 [2] 01 c2 [2] 07 f7 [2] 29 f7 [2] 16 eb }

  condition:
    any of them
}