rule TTP_XOR_WriteProcessMemory_9797 {
  strings:
    $key_9797 = { c0 e5 [2] f2 c7 [2] f4 f2 [2] da f2 [2] e5 ee }

  condition:
    any of them
}