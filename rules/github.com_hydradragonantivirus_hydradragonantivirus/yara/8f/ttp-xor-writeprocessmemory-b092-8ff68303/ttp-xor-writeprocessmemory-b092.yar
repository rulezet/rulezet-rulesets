rule TTP_XOR_WriteProcessMemory_b092 {
  strings:
    $key_b092 = { e7 e0 [2] d5 c2 [2] d3 f7 [2] fd f7 [2] c2 eb }

  condition:
    any of them
}