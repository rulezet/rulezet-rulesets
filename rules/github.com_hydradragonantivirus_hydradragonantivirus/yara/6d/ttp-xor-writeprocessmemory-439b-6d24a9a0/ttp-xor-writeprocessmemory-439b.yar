rule TTP_XOR_WriteProcessMemory_439b {
  strings:
    $key_439b = { 14 e9 [2] 26 cb [2] 20 fe [2] 0e fe [2] 31 e2 }

  condition:
    any of them
}