rule TTP_XOR_WriteProcessMemory_9460 {
  strings:
    $key_9460 = { c3 12 [2] f1 30 [2] f7 05 [2] d9 05 [2] e6 19 }

  condition:
    any of them
}