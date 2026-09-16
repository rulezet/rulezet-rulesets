rule TTP_XOR_WriteProcessMemory_94b9 {
  strings:
    $key_94b9 = { c3 cb [2] f1 e9 [2] f7 dc [2] d9 dc [2] e6 c0 }

  condition:
    any of them
}