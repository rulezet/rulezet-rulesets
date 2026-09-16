rule TTP_XOR_WriteProcessMemory_93a6 {
  strings:
    $key_93a6 = { c4 d4 [2] f6 f6 [2] f0 c3 [2] de c3 [2] e1 df }

  condition:
    any of them
}