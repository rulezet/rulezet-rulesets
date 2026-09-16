rule TTP_XOR_WriteProcessMemory_91c4 {
  strings:
    $key_91c4 = { c6 b6 [2] f4 94 [2] f2 a1 [2] dc a1 [2] e3 bd }

  condition:
    any of them
}