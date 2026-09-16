rule TTP_XOR_WriteProcessMemory_929b {
  strings:
    $key_929b = { c5 e9 [2] f7 cb [2] f1 fe [2] df fe [2] e0 e2 }

  condition:
    any of them
}