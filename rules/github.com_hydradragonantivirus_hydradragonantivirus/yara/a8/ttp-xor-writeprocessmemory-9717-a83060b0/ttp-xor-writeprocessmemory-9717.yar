rule TTP_XOR_WriteProcessMemory_9717 {
  strings:
    $key_9717 = { c0 65 [2] f2 47 [2] f4 72 [2] da 72 [2] e5 6e }

  condition:
    any of them
}