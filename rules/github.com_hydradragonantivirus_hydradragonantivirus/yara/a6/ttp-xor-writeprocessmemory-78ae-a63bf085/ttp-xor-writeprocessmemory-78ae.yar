rule TTP_XOR_WriteProcessMemory_78ae {
  strings:
    $key_78ae = { 2f dc [2] 1d fe [2] 1b cb [2] 35 cb [2] 0a d7 }

  condition:
    any of them
}