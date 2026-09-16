rule TTP_XOR_WriteProcessMemory_039b {
  strings:
    $key_039b = { 54 e9 [2] 66 cb [2] 60 fe [2] 4e fe [2] 71 e2 }

  condition:
    any of them
}