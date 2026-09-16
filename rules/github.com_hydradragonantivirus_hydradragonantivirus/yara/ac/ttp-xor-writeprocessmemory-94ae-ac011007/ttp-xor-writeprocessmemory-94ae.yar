rule TTP_XOR_WriteProcessMemory_94ae {
  strings:
    $key_94ae = { c3 dc [2] f1 fe [2] f7 cb [2] d9 cb [2] e6 d7 }

  condition:
    any of them
}