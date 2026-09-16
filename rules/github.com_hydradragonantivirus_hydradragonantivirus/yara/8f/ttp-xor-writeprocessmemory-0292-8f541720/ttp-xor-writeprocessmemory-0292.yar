rule TTP_XOR_WriteProcessMemory_0292 {
  strings:
    $key_0292 = { 55 e0 [2] 67 c2 [2] 61 f7 [2] 4f f7 [2] 70 eb }

  condition:
    any of them
}