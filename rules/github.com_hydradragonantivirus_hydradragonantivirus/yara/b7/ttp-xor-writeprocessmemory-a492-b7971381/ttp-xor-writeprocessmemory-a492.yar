rule TTP_XOR_WriteProcessMemory_a492 {
  strings:
    $key_a492 = { f3 e0 [2] c1 c2 [2] c7 f7 [2] e9 f7 [2] d6 eb }

  condition:
    any of them
}