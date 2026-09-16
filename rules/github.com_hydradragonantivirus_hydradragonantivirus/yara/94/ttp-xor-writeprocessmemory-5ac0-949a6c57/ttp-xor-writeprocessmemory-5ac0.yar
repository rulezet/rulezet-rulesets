rule TTP_XOR_WriteProcessMemory_5ac0 {
  strings:
    $key_5ac0 = { 0d b2 [2] 3f 90 [2] 39 a5 [2] 17 a5 [2] 28 b9 }

  condition:
    any of them
}