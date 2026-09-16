rule TTP_XOR_WriteProcessMemory_9410 {
  strings:
    $key_9410 = { c3 62 [2] f1 40 [2] f7 75 [2] d9 75 [2] e6 69 }

  condition:
    any of them
}