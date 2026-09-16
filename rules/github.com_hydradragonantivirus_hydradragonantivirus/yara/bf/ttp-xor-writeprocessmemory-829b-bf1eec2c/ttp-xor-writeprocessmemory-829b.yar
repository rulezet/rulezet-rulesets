rule TTP_XOR_WriteProcessMemory_829b {
  strings:
    $key_829b = { d5 e9 [2] e7 cb [2] e1 fe [2] cf fe [2] f0 e2 }

  condition:
    any of them
}