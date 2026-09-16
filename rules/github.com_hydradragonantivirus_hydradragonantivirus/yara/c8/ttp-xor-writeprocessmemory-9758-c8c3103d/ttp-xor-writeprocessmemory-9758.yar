rule TTP_XOR_WriteProcessMemory_9758 {
  strings:
    $key_9758 = { c0 2a [2] f2 08 [2] f4 3d [2] da 3d [2] e5 21 }

  condition:
    any of them
}