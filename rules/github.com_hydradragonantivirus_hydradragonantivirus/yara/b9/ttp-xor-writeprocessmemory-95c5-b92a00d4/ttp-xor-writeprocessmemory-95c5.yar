rule TTP_XOR_WriteProcessMemory_95c5 {
  strings:
    $key_95c5 = { c2 b7 [2] f0 95 [2] f6 a0 [2] d8 a0 [2] e7 bc }

  condition:
    any of them
}