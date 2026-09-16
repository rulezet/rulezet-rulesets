rule TTP_XOR_WriteProcessMemory_8749 {
  strings:
    $key_8749 = { d0 3b [2] e2 19 [2] e4 2c [2] ca 2c [2] f5 30 }

  condition:
    any of them
}