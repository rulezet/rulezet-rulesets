rule TTP_XOR_WriteProcessMemory_d19b {
  strings:
    $key_d19b = { 86 e9 [2] b4 cb [2] b2 fe [2] 9c fe [2] a3 e2 }

  condition:
    any of them
}