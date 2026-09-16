rule TTP_XOR_WriteProcessMemory_9748 {
  strings:
    $key_9748 = { c0 3a [2] f2 18 [2] f4 2d [2] da 2d [2] e5 31 }

  condition:
    any of them
}