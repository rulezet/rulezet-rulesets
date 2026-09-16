rule TTP_XOR_WriteProcessMemory_9364 {
  strings:
    $key_9364 = { c4 16 [2] f6 34 [2] f0 01 [2] de 01 [2] e1 1d }

  condition:
    any of them
}