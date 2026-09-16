rule TTP_XOR_WriteProcessMemory_3c9b {
  strings:
    $key_3c9b = { 6b e9 [2] 59 cb [2] 5f fe [2] 71 fe [2] 4e e2 }

  condition:
    any of them
}