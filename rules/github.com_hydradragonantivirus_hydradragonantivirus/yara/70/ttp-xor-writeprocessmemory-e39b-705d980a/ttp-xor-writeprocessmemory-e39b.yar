rule TTP_XOR_WriteProcessMemory_e39b {
  strings:
    $key_e39b = { b4 e9 [2] 86 cb [2] 80 fe [2] ae fe [2] 91 e2 }

  condition:
    any of them
}