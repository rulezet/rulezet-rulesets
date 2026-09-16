rule TTP_XOR_WriteProcessMemory_9464 {
  strings:
    $key_9464 = { c3 16 [2] f1 34 [2] f7 01 [2] d9 01 [2] e6 1d }

  condition:
    any of them
}