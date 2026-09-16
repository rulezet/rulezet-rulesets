rule TTP_XOR_WriteProcessMemory_f09b {
  strings:
    $key_f09b = { a7 e9 [2] 95 cb [2] 93 fe [2] bd fe [2] 82 e2 }

  condition:
    any of them
}