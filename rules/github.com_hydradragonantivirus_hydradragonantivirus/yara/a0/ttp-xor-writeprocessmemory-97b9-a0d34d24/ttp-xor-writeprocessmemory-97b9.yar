rule TTP_XOR_WriteProcessMemory_97b9 {
  strings:
    $key_97b9 = { c0 cb [2] f2 e9 [2] f4 dc [2] da dc [2] e5 c0 }

  condition:
    any of them
}