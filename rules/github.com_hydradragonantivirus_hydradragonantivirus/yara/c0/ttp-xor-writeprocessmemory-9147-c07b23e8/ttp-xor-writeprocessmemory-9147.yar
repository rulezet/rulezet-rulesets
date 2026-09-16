rule TTP_XOR_WriteProcessMemory_9147 {
  strings:
    $key_9147 = { c6 35 [2] f4 17 [2] f2 22 [2] dc 22 [2] e3 3e }

  condition:
    any of them
}