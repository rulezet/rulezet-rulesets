rule TTP_XOR_WriteProcessMemory_9347 {
  strings:
    $key_9347 = { c4 35 [2] f6 17 [2] f0 22 [2] de 22 [2] e1 3e }

  condition:
    any of them
}