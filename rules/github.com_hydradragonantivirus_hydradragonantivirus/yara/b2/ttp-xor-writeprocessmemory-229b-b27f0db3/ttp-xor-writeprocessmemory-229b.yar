rule TTP_XOR_WriteProcessMemory_229b {
  strings:
    $key_229b = { 75 e9 [2] 47 cb [2] 41 fe [2] 6f fe [2] 50 e2 }

  condition:
    any of them
}