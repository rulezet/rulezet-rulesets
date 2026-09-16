rule TTP_XOR_WriteProcessMemory_6292 {
  strings:
    $key_6292 = { 35 e0 [2] 07 c2 [2] 01 f7 [2] 2f f7 [2] 10 eb }

  condition:
    any of them
}