rule TTP_XOR_WriteProcessMemory_9492 {
  strings:
    $key_9492 = { c3 e0 [2] f1 c2 [2] f7 f7 [2] d9 f7 [2] e6 eb }

  condition:
    any of them
}