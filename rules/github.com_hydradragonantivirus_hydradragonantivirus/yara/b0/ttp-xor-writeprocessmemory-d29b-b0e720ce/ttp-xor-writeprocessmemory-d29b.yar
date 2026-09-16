rule TTP_XOR_WriteProcessMemory_d29b {
  strings:
    $key_d29b = { 85 e9 [2] b7 cb [2] b1 fe [2] 9f fe [2] a0 e2 }

  condition:
    any of them
}