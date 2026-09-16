rule TTP_XOR_WriteProcessMemory_95c4 {
  strings:
    $key_95c4 = { c2 b6 [2] f0 94 [2] f6 a1 [2] d8 a1 [2] e7 bd }

  condition:
    any of them
}