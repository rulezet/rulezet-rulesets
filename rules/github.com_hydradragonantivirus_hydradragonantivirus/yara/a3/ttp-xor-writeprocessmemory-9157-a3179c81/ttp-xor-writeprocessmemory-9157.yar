rule TTP_XOR_WriteProcessMemory_9157 {
  strings:
    $key_9157 = { c6 25 [2] f4 07 [2] f2 32 [2] dc 32 [2] e3 2e }

  condition:
    any of them
}