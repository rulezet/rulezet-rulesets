rule TTP_XOR_WriteProcessMemory_9714 {
  strings:
    $key_9714 = { c0 66 [2] f2 44 [2] f4 71 [2] da 71 [2] e5 6d }

  condition:
    any of them
}