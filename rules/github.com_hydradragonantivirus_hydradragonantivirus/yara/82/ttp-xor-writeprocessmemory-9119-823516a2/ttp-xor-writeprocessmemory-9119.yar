rule TTP_XOR_WriteProcessMemory_9119 {
  strings:
    $key_9119 = { c6 6b [2] f4 49 [2] f2 7c [2] dc 7c [2] e3 60 }

  condition:
    any of them
}