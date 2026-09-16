rule TTP_XOR_WriteProcessMemory_c79b {
  strings:
    $key_c79b = { 90 e9 [2] a2 cb [2] a4 fe [2] 8a fe [2] b5 e2 }

  condition:
    any of them
}