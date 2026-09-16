rule TTP_XOR_WriteProcessMemory_9539 {
  strings:
    $key_9539 = { c2 4b [2] f0 69 [2] f6 5c [2] d8 5c [2] e7 40 }

  condition:
    any of them
}