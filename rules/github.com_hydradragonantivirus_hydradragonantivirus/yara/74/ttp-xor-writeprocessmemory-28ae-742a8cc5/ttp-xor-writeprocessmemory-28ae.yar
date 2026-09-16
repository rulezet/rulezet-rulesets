rule TTP_XOR_WriteProcessMemory_28ae {
  strings:
    $key_28ae = { 7f dc [2] 4d fe [2] 4b cb [2] 65 cb [2] 5a d7 }

  condition:
    any of them
}