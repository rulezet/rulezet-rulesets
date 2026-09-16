rule TTP_XOR_WriteProcessMemory_9747 {
  strings:
    $key_9747 = { c0 35 [2] f2 17 [2] f4 22 [2] da 22 [2] e5 3e }

  condition:
    any of them
}