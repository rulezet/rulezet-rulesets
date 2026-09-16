rule TTP_XOR_WriteProcessMemory_8704 {
  strings:
    $key_8704 = { d0 76 [2] e2 54 [2] e4 61 [2] ca 61 [2] f5 7d }

  condition:
    any of them
}