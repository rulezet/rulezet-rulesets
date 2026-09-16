rule TTP_XOR_WriteProcessMemory_9520 {
  strings:
    $key_9520 = { c2 52 [2] f0 70 [2] f6 45 [2] d8 45 [2] e7 59 }

  condition:
    any of them
}