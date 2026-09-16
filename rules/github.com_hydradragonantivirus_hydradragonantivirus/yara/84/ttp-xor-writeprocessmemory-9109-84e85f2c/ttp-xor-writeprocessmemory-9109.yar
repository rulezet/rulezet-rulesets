rule TTP_XOR_WriteProcessMemory_9109 {
  strings:
    $key_9109 = { c6 7b [2] f4 59 [2] f2 6c [2] dc 6c [2] e3 70 }

  condition:
    any of them
}