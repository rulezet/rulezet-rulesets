rule TTP_XOR_WriteProcessMemory_9344 {
  strings:
    $key_9344 = { c4 36 [2] f6 14 [2] f0 21 [2] de 21 [2] e1 3d }

  condition:
    any of them
}