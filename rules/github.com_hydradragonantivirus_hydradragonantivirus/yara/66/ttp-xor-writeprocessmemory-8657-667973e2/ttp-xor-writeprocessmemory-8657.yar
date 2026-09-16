rule TTP_XOR_WriteProcessMemory_8657 {
  strings:
    $key_8657 = { d1 25 [2] e3 07 [2] e5 32 [2] cb 32 [2] f4 2e }

  condition:
    any of them
}