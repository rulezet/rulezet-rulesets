rule TTP_XOR_WriteProcessMemory_9436 {
  strings:
    $key_9436 = { c3 44 [2] f1 66 [2] f7 53 [2] d9 53 [2] e6 4f }

  condition:
    any of them
}