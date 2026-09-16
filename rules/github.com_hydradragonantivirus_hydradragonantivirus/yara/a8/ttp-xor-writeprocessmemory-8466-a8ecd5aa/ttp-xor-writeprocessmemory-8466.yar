rule TTP_XOR_WriteProcessMemory_8466 {
  strings:
    $key_8466 = { d3 14 [2] e1 36 [2] e7 03 [2] c9 03 [2] f6 1f }

  condition:
    any of them
}