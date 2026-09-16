rule TTP_XOR_WriteProcessMemory_ef9b {
  strings:
    $key_ef9b = { b8 e9 [2] 8a cb [2] 8c fe [2] a2 fe [2] 9d e2 }

  condition:
    any of them
}