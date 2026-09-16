rule TTP_XOR_WriteProcessMemory_9411 {
  strings:
    $key_9411 = { c3 63 [2] f1 41 [2] f7 74 [2] d9 74 [2] e6 68 }

  condition:
    any of them
}