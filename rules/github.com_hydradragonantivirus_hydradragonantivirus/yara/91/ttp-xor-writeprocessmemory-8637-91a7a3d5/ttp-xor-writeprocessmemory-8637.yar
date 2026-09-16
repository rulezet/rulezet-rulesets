rule TTP_XOR_WriteProcessMemory_8637 {
  strings:
    $key_8637 = { d1 45 [2] e3 67 [2] e5 52 [2] cb 52 [2] f4 4e }

  condition:
    any of them
}