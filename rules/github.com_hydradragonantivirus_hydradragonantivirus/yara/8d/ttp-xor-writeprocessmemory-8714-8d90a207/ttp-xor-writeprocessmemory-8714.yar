rule TTP_XOR_WriteProcessMemory_8714 {
  strings:
    $key_8714 = { d0 66 [2] e2 44 [2] e4 71 [2] ca 71 [2] f5 6d }

  condition:
    any of them
}