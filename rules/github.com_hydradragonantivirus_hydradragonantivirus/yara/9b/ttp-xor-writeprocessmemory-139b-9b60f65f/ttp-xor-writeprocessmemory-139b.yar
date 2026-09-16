rule TTP_XOR_WriteProcessMemory_139b {
  strings:
    $key_139b = { 44 e9 [2] 76 cb [2] 70 fe [2] 5e fe [2] 61 e2 }

  condition:
    any of them
}