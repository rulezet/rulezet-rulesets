rule TTP_XOR_WriteProcessMemory_9128 {
  strings:
    $key_9128 = { c6 5a [2] f4 78 [2] f2 4d [2] dc 4d [2] e3 51 }

  condition:
    any of them
}