rule TTP_XOR_WriteProcessMemory_08ae {
  strings:
    $key_08ae = { 5f dc [2] 6d fe [2] 6b cb [2] 45 cb [2] 7a d7 }

  condition:
    any of them
}