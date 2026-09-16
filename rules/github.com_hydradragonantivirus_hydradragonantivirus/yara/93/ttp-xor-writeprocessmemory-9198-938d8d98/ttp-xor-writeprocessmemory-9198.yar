rule TTP_XOR_WriteProcessMemory_9198 {
  strings:
    $key_9198 = { c6 ea [2] f4 c8 [2] f2 fd [2] dc fd [2] e3 e1 }

  condition:
    any of them
}