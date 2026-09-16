rule TTP_XOR_WriteProcessMemory_ca9b {
  strings:
    $key_ca9b = { 9d e9 [2] af cb [2] a9 fe [2] 87 fe [2] b8 e2 }

  condition:
    any of them
}