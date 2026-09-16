rule TTP_XOR_WriteProcessMemory_919b {
  strings:
    $key_919b = { c6 e9 [2] f4 cb [2] f2 fe [2] dc fe [2] e3 e2 }

  condition:
    any of them
}