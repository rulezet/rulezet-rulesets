rule TTP_XOR_WriteProcessMemory_2292 {
  strings:
    $key_2292 = { 75 e0 [2] 47 c2 [2] 41 f7 [2] 6f f7 [2] 50 eb }

  condition:
    any of them
}