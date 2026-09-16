rule TTP_XOR_WriteProcessMemory_6a8c {
  strings:
    $key_6a8c = { 3d fe [2] 0f dc [2] 09 e9 [2] 27 e9 [2] 18 f5 }

  condition:
    any of them
}