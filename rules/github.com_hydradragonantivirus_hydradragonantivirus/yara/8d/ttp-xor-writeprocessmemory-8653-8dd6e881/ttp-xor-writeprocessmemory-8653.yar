rule TTP_XOR_WriteProcessMemory_8653 {
  strings:
    $key_8653 = { d1 21 [2] e3 03 [2] e5 36 [2] cb 36 [2] f4 2a }

  condition:
    any of them
}