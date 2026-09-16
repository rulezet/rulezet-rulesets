rule TTP_XOR_WriteProcessMemory_709b {
  strings:
    $key_709b = { 27 e9 [2] 15 cb [2] 13 fe [2] 3d fe [2] 02 e2 }

  condition:
    any of them
}