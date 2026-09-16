rule TTP_XOR_WriteProcessMemory_9557 {
  strings:
    $key_9557 = { c2 25 [2] f0 07 [2] f6 32 [2] d8 32 [2] e7 2e }

  condition:
    any of them
}