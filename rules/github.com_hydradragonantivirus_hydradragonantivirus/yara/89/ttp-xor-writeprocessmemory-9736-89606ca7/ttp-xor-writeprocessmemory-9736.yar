rule TTP_XOR_WriteProcessMemory_9736 {
  strings:
    $key_9736 = { c0 44 [2] f2 66 [2] f4 53 [2] da 53 [2] e5 4f }

  condition:
    any of them
}