rule TTP_XOR_WriteProcessMemory_9111 {
  strings:
    $key_9111 = { c6 63 [2] f4 41 [2] f2 74 [2] dc 74 [2] e3 68 }

  condition:
    any of them
}