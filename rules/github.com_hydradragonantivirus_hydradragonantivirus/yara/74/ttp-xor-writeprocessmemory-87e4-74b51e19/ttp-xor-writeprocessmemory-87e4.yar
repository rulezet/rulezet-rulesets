rule TTP_XOR_WriteProcessMemory_87e4 {
  strings:
    $key_87e4 = { d0 96 [2] e2 b4 [2] e4 81 [2] ca 81 [2] f5 9d }

  condition:
    any of them
}