rule TTP_XOR_WriteProcessMemory_9334 {
  strings:
    $key_9334 = { c4 46 [2] f6 64 [2] f0 51 [2] de 51 [2] e1 4d }

  condition:
    any of them
}