rule TTP_XOR_WriteProcessMemory_9737 {
  strings:
    $key_9737 = { c0 45 [2] f2 67 [2] f4 52 [2] da 52 [2] e5 4e }

  condition:
    any of them
}