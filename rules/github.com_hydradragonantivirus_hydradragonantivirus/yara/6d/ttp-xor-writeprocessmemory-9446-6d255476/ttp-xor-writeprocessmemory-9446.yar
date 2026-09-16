rule TTP_XOR_WriteProcessMemory_9446 {
  strings:
    $key_9446 = { c3 34 [2] f1 16 [2] f7 23 [2] d9 23 [2] e6 3f }

  condition:
    any of them
}