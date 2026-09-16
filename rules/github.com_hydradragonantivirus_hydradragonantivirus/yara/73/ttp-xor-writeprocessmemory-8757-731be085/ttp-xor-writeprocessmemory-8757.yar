rule TTP_XOR_WriteProcessMemory_8757 {
  strings:
    $key_8757 = { d0 25 [2] e2 07 [2] e4 32 [2] ca 32 [2] f5 2e }

  condition:
    any of them
}