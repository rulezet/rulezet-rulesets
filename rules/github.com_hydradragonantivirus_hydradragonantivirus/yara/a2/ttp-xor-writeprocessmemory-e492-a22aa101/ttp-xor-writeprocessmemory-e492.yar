rule TTP_XOR_WriteProcessMemory_e492 {
  strings:
    $key_e492 = { b3 e0 [2] 81 c2 [2] 87 f7 [2] a9 f7 [2] 96 eb }

  condition:
    any of them
}