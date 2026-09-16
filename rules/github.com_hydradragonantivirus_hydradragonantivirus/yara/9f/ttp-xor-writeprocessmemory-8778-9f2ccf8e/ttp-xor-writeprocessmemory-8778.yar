rule TTP_XOR_WriteProcessMemory_8778 {
  strings:
    $key_8778 = { d0 0a [2] e2 28 [2] e4 1d [2] ca 1d [2] f5 01 }

  condition:
    any of them
}