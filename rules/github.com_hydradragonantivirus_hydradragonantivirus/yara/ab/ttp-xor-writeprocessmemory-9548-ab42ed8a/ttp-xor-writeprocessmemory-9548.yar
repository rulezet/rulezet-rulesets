rule TTP_XOR_WriteProcessMemory_9548 {
  strings:
    $key_9548 = { c2 3a [2] f0 18 [2] f6 2d [2] d8 2d [2] e7 31 }

  condition:
    any of them
}