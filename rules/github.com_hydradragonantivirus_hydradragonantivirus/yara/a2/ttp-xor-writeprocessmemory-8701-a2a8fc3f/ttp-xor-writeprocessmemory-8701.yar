rule TTP_XOR_WriteProcessMemory_8701 {
  strings:
    $key_8701 = { d0 73 [2] e2 51 [2] e4 64 [2] ca 64 [2] f5 78 }

  condition:
    any of them
}