rule TTP_XOR_WriteProcessMemory_8573 {
  strings:
    $key_8573 = { d2 01 [2] e0 23 [2] e6 16 [2] c8 16 [2] f7 0a }

  condition:
    any of them
}