rule TTP_XOR_WriteProcessMemory_9768 {
  strings:
    $key_9768 = { c0 1a [2] f2 38 [2] f4 0d [2] da 0d [2] e5 11 }

  condition:
    any of them
}