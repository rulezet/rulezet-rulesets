rule TTP_XOR_WriteProcessMemory_d79b {
  strings:
    $key_d79b = { 80 e9 [2] b2 cb [2] b4 fe [2] 9a fe [2] a5 e2 }

  condition:
    any of them
}