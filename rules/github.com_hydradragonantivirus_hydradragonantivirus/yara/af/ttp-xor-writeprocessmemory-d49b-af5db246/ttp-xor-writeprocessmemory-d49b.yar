rule TTP_XOR_WriteProcessMemory_d49b {
  strings:
    $key_d49b = { 83 e9 [2] b1 cb [2] b7 fe [2] 99 fe [2] a6 e2 }

  condition:
    any of them
}