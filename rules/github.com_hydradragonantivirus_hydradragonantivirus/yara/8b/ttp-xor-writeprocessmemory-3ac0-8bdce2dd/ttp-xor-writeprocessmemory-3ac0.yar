rule TTP_XOR_WriteProcessMemory_3ac0 {
  strings:
    $key_3ac0 = { 6d b2 [2] 5f 90 [2] 59 a5 [2] 77 a5 [2] 48 b9 }

  condition:
    any of them
}