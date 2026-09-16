rule TTP_XOR_WriteProcessMemory_e09b {
  strings:
    $key_e09b = { b7 e9 [2] 85 cb [2] 83 fe [2] ad fe [2] 92 e2 }

  condition:
    any of them
}