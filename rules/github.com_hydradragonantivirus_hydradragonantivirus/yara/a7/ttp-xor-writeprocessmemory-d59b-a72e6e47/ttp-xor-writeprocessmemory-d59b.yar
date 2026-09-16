rule TTP_XOR_WriteProcessMemory_d59b {
  strings:
    $key_d59b = { 82 e9 [2] b0 cb [2] b6 fe [2] 98 fe [2] a7 e2 }

  condition:
    any of them
}