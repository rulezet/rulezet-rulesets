rule TTP_XOR_WriteProcessMemory_9764 {
  strings:
    $key_9764 = { c0 16 [2] f2 34 [2] f4 01 [2] da 01 [2] e5 1d }

  condition:
    any of them
}