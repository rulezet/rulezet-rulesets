rule TTP_XOR_WriteProcessMemory_93c4 {
  strings:
    $key_93c4 = { c4 b6 [2] f6 94 [2] f0 a1 [2] de a1 [2] e1 bd }

  condition:
    any of them
}