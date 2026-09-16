rule TTP_XOR_WriteProcessMemory_519b {
  strings:
    $key_519b = { 06 e9 [2] 34 cb [2] 32 fe [2] 1c fe [2] 23 e2 }

  condition:
    any of them
}