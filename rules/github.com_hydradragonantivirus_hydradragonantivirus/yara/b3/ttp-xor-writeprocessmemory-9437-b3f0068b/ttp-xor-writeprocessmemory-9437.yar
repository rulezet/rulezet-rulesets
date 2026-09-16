rule TTP_XOR_WriteProcessMemory_9437 {
  strings:
    $key_9437 = { c3 45 [2] f1 67 [2] f7 52 [2] d9 52 [2] e6 4e }

  condition:
    any of them
}