rule TTP_XOR_WriteProcessMemory_c59b {
  strings:
    $key_c59b = { 92 e9 [2] a0 cb [2] a6 fe [2] 88 fe [2] b7 e2 }

  condition:
    any of them
}