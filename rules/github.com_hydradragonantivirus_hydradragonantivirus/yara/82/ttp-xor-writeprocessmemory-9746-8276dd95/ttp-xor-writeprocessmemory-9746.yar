rule TTP_XOR_WriteProcessMemory_9746 {
  strings:
    $key_9746 = { c0 34 [2] f2 16 [2] f4 23 [2] da 23 [2] e5 3f }

  condition:
    any of them
}