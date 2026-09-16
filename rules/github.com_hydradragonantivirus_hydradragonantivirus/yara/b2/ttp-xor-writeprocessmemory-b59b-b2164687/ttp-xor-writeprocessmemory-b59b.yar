rule TTP_XOR_WriteProcessMemory_b59b {
  strings:
    $key_b59b = { e2 e9 [2] d0 cb [2] d6 fe [2] f8 fe [2] c7 e2 }

  condition:
    any of them
}