rule TTP_XOR_WriteProcessMemory_9004 {
  strings:
    $key_9004 = { c7 76 [2] f5 54 [2] f3 61 [2] dd 61 [2] e2 7d }

  condition:
    any of them
}