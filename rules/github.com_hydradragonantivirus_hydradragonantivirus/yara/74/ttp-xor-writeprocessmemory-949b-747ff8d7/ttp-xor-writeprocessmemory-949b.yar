rule TTP_XOR_WriteProcessMemory_949b {
  strings:
    $key_949b = { c3 e9 [2] f1 cb [2] f7 fe [2] d9 fe [2] e6 e2 }

  condition:
    any of them
}