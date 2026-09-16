rule TTP_XOR_WriteProcessMemory_379b {
  strings:
    $key_379b = { 60 e9 [2] 52 cb [2] 54 fe [2] 7a fe [2] 45 e2 }

  condition:
    any of them
}