rule TTP_XOR_WriteProcessMemory_dd9b {
  strings:
    $key_dd9b = { 8a e9 [2] b8 cb [2] be fe [2] 90 fe [2] af e2 }

  condition:
    any of them
}