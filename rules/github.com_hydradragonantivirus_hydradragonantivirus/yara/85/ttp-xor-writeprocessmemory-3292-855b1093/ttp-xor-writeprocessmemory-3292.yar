rule TTP_XOR_WriteProcessMemory_3292 {
  strings:
    $key_3292 = { 65 e0 [2] 57 c2 [2] 51 f7 [2] 7f f7 [2] 40 eb }

  condition:
    any of them
}