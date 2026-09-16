rule TTP_XOR_WriteProcessMemory_8603 {
  strings:
    $key_8603 = { d1 71 [2] e3 53 [2] e5 66 [2] cb 66 [2] f4 7a }

  condition:
    any of them
}