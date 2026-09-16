rule TTP_XOR_WriteProcessMemory_239b {
  strings:
    $key_239b = { 74 e9 [2] 46 cb [2] 40 fe [2] 6e fe [2] 51 e2 }

  condition:
    any of them
}