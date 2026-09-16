rule TTP_XOR_WriteProcessMemory_9134 {
  strings:
    $key_9134 = { c6 46 [2] f4 64 [2] f2 51 [2] dc 51 [2] e3 4d }

  condition:
    any of them
}