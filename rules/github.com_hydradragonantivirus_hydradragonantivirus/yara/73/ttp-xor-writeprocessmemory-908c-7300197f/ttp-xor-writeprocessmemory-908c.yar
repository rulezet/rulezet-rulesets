rule TTP_XOR_WriteProcessMemory_908c {
  strings:
    $key_908c = { c7 fe [2] f5 dc [2] f3 e9 [2] dd e9 [2] e2 f5 }

  condition:
    any of them
}