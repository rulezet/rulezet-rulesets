rule TTP_XOR_WriteProcessMemory_b29b {
  strings:
    $key_b29b = { e5 e9 [2] d7 cb [2] d1 fe [2] ff fe [2] c0 e2 }

  condition:
    any of them
}