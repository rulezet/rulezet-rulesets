rule TTP_XOR_WriteProcessMemory_58ae {
  strings:
    $key_58ae = { 0f dc [2] 3d fe [2] 3b cb [2] 15 cb [2] 2a d7 }

  condition:
    any of them
}