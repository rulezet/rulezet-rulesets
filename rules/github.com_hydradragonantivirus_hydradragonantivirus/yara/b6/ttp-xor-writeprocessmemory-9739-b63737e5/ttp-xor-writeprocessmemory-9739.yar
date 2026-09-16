rule TTP_XOR_WriteProcessMemory_9739 {
  strings:
    $key_9739 = { c0 4b [2] f2 69 [2] f4 5c [2] da 5c [2] e5 40 }

  condition:
    any of them
}