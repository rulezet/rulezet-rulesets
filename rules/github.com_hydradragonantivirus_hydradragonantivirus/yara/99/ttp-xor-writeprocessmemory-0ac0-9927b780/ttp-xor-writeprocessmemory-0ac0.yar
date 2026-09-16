rule TTP_XOR_WriteProcessMemory_0ac0 {
  strings:
    $key_0ac0 = { 5d b2 [2] 6f 90 [2] 69 a5 [2] 47 a5 [2] 78 b9 }

  condition:
    any of them
}