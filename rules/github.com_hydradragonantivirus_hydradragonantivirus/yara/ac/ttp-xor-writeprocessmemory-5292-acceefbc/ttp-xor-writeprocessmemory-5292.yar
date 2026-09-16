rule TTP_XOR_WriteProcessMemory_5292 {
  strings:
    $key_5292 = { 05 e0 [2] 37 c2 [2] 31 f7 [2] 1f f7 [2] 20 eb }

  condition:
    any of them
}