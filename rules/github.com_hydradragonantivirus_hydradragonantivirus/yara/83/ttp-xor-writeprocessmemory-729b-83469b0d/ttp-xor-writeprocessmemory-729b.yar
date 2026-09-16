rule TTP_XOR_WriteProcessMemory_729b {
  strings:
    $key_729b = { 25 e9 [2] 17 cb [2] 11 fe [2] 3f fe [2] 00 e2 }

  condition:
    any of them
}