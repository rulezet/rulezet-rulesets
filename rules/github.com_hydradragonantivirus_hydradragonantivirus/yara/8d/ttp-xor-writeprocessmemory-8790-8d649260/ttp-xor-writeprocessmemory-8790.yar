rule TTP_XOR_WriteProcessMemory_8790 {
  strings:
    $key_8790 = { d0 e2 [2] e2 c0 [2] e4 f5 [2] ca f5 [2] f5 e9 }

  condition:
    any of them
}