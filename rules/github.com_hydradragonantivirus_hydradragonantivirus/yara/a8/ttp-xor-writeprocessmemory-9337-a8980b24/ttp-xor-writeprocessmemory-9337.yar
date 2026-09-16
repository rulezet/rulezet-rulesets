rule TTP_XOR_WriteProcessMemory_9337 {
  strings:
    $key_9337 = { c4 45 [2] f6 67 [2] f0 52 [2] de 52 [2] e1 4e }

  condition:
    any of them
}