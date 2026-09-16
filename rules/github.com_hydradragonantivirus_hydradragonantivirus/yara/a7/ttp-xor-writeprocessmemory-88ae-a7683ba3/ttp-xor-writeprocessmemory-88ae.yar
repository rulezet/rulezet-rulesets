rule TTP_XOR_WriteProcessMemory_88ae {
  strings:
    $key_88ae = { df dc [2] ed fe [2] eb cb [2] c5 cb [2] fa d7 }

  condition:
    any of them
}