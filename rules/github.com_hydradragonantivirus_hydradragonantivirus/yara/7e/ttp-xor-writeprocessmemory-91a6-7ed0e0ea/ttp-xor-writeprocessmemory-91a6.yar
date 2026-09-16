rule TTP_XOR_WriteProcessMemory_91a6 {
  strings:
    $key_91a6 = { c6 d4 [2] f4 f6 [2] f2 c3 [2] dc c3 [2] e3 df }

  condition:
    any of them
}