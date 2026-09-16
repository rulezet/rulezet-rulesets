rule TTP_XOR_WriteProcessMemory_8190 {
  strings:
    $key_8190 = { d6 e2 [2] e4 c0 [2] e2 f5 [2] cc f5 [2] f3 e9 }

  condition:
    any of them
}