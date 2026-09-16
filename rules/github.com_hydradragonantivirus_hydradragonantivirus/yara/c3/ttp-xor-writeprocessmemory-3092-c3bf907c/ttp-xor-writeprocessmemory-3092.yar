rule TTP_XOR_WriteProcessMemory_3092 {
  strings:
    $key_3092 = { 67 e0 [2] 55 c2 [2] 53 f7 [2] 7d f7 [2] 42 eb }

  condition:
    any of them
}