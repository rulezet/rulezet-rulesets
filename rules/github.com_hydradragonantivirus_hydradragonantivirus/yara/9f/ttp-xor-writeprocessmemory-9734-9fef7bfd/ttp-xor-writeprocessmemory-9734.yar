rule TTP_XOR_WriteProcessMemory_9734 {
  strings:
    $key_9734 = { c0 46 [2] f2 64 [2] f4 51 [2] da 51 [2] e5 4d }

  condition:
    any of them
}