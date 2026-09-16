rule TTP_XOR_WriteProcessMemory_9149 {
  strings:
    $key_9149 = { c6 3b [2] f4 19 [2] f2 2c [2] dc 2c [2] e3 30 }

  condition:
    any of them
}