rule TTP_XOR_WriteProcessMemory_9402 {
  strings:
    $key_9402 = { c3 70 [2] f1 52 [2] f7 67 [2] d9 67 [2] e6 7b }

  condition:
    any of them
}