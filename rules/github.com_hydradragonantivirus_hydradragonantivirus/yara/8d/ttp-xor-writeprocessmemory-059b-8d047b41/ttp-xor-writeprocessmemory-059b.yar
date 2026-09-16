rule TTP_XOR_WriteProcessMemory_059b {
  strings:
    $key_059b = { 52 e9 [2] 60 cb [2] 66 fe [2] 48 fe [2] 77 e2 }

  condition:
    any of them
}