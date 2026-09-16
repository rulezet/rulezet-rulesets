rule TTP_XOR_WriteProcessMemory_8515 {
  strings:
    $key_8515 = { d2 67 [2] e0 45 [2] e6 70 [2] c8 70 [2] f7 6c }

  condition:
    any of them
}