rule TTP_XOR_WriteProcessMemory_91b9 {
  strings:
    $key_91b9 = { c6 cb [2] f4 e9 [2] f2 dc [2] dc dc [2] e3 c0 }

  condition:
    any of them
}